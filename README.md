# Hacking the PostgREST Headers: Oh, the Things You Can Do!
When using the Supabase Javascript Client, reading the PostgREST headers gives us all sorts of useful information for logging and security purposes.

What does your database know about your users?  If you're using the Supabase Javascript Client (which wraps PostgREST), then, well, plenty!  

Luke Bechtel from [Revaly](https://revaly.com) recently asked "is there any way to get things like **Client IP Address** or **Browser Type** from inside a PostgreSQL trigger or RLS (Row Level Security) Policy?"  Well, since the Supabase client uses PostgREST, and PostgREST is a web tool, then it should have full access to the server's request object.  And indeed, it does.

### Interesting Use Cases
Why is this useful or important?  Imagine these use cases:

- Whitelisting IPs: only allow users to select, insert, update, or delete if they're coming from a pre-defined list of IP addresses.
- Origin Restrictions: allow a feature only during development (when the request is coming from **localhost** but not your production domain).
- Platform Checking: only allow users from mobile platforms to use your application (no desktop browsers).
- Logging: Log the user's IP address and browser User Agent in your database along with their data.
- Version Requirements: only allow clients coming from the most recent version of the Supabase Javascript Client Library.

Of course, if the user is logged into our app, this is already in addition to the users email address and user id, which we already have access to via `auth.email()` and `auth.uid()`.

### Getting Access to the Request Headers
How can we get access to all this useful information?  By using the PostgreSQL `current_setting` function, we can access the `request.headers` liks this: `current_setting('request.headers', true)`.  So, to put that into a useful function, we get:

```sql
CREATE OR REPLACE FUNCTION get_headers() RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
    SELECT current_setting('request.headers', true)::json
$$;
```

This function returns a **JSON** object with all the header information from the request.  We get things like:

```
accept-encoding: "gzip"
accept-language: "en-US,en;q=0.9"
host: "localhost:3000"
origin: "http://localhost:8100"
referer: "http://localhost:8100/"
user-agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
x-client-info: "supabase-js/1.35.7"
x-consumer-username: "anon-key"
x-forwarded-for: "142.251.46.206, 20.112.52.29"
x-forwarded-host: "xxxxxxxxxxxxxxxx.supabase.co"
```

If we want to get the data from a specific header, we can create this function:

```sql
CREATE OR REPLACE FUNCTION get_header(item text) RETURNS text
    LANGUAGE sql STABLE
    AS $$
    SELECT (current_setting('request.headers', true)::json)->>item
$$;
```

This allows us to get the text value for any specified header, such as: `get_header('user-agent')`.

### Using the Results in a RLS (Row Level Security) Policy

Let's say we want to only allow records to be inserted into our table `beta_tests` if the request is coming from a server running on `localhost`, port `3000`.

```sql
CREATE POLICY "only allow inserts on public.beta_tests from localhost:3000" 
ON public.beta_tests 
FOR INSERT 
WITH CHECK (get_header('host')='localhost:3000');
```

For security purposes, we can restict the usage for a table based on a whitelisted set of IPs.  First, we need to get the user's IP address, which is found in `x-forwarded-for`, but that has 2 IP addresses separated by commas, and we only want the first one.  So we can use the PostgreSQL `SPLIT_PART` function, which is similar to the Javascript `split` function: `SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1)`.  Note how we concatenate a comma to the `x-forwarded-for` header (`get_header('x-forwarded-for') || ','`), just in case there's an empty string there?

Now that we have the user's IP address, we can test to see if it's in our whitelist set:

```sql
CREATE POLICY "only allow access to table_for_internal_use_only from a set of IPs" ON "public"."table_for_internal_use_only"
AS PERMISSIVE FOR ALL
TO public
USING (SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1) = ANY (ARRAY['123.44.152.151','203.44.11.22','11.4.102.33']))
WITH CHECK (SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1) = ANY (ARRAY['123.44.152.151','203.44.11.22','11.4.102.33']));
```

You could extend this by creating a table of IP addresses and check against that table (`(SELECT count(*) from my_whitelist_table where ip = SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1)) > 0`), but be careful, this adds an extra lookup to another table, and this slows down your RLS policy considerably and could lead to scaling problems down the road.

### Using the Results in a PostgreSQL Trigger
Let's create a log table caled `log_table`, and then for every record inserted into our `test_table`, we'll log a record there with the user's `user_agent`, `host`, `origin`, `referer`, and `ip`:

```sql
CREATE TABLE IF NOT EXISTS log_table (id serial primary key, table_name text, key text, created_at timestamptz DEFAULT now(), user_agent text, host text, origin text, referer text, ip text);

CREATE OR REPLACE FUNCTION log_user_data()
  RETURNS trigger AS
$$
BEGIN
  INSERT INTO log_table(table_name, key, user_agent, host, origin, referer, ip)
  VALUES(TG_TABLE_NAME::regclass::text, NEW.id::text, get_header('user-agent'), get_header('host'), get_header('origin'), get_header('referer'), SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1));
  RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER test_trigger
  AFTER INSERT
  ON test_table
  FOR EACH ROW
  EXECUTE PROCEDURE log_user_data();
```

Things of note here:  
- `TG_TABLE_NAME::regclass::text` returns the current table name in our trigger (so we can re-use this trigger on other tables!)
- `NEW.id::text` converts the `id` field of the current table to text (a string).  I use a `UUID` as the `id` field for almost every table I create, so this should work just fine.  If you use a different convention or primary key type, you may have to alter this.
- `SPLIT_PART(get_header('x-forwarded-for') || ',', ',', 1)`, as mentioned earlier, grabs the first `ip` found in the `x-forwarded-for` header.

### Other Interesting Tidbits from the User-Agent
We can parse the `user-agent` header to get relevant information, such as:

Is the user running on a Windows platform:
`get_header('user-agent') LIKE '%Windows%'`
Or Mac:
`get_header('user-agent') LIKE '%Mac OS X%'`
Is the user on a Mobile device:
`get_header('user-agent') LIKE 'Mobile/%'`
Check iOS Major Version:
`get_header('user-agent') LIKE '%iPhone OS 16%'`

The `user-agent` isn't the most accurate way to get this information, though, and `user-agent`s are always subject to change (and can be forged) so be careful with this.

### Other Caveats and Warnings
You may find additional headers beyond the ones listed here available to you when testing this, but it's best not to rely on them, as they:
1. may not be available on every platform or device (some headers exist on desktop systems but not mobile systems, for instance)
2. may change or go away completely based on infrastructure changes or changes to PostgREST or the Supabase Client Libraries.

### Conclusion
PostgREST exposes some really useful request headers that give PostgreSQL functions the power to do some things that previously required a separate middleware tier.  Moving this functionality into the database eliminates the need for that extra tier and might also speed up your application by reducing extra network round-trips.  It also allows you to add an extra security layer at the database level, so you can allow or restrict access based on IP address, host name, client type, Javascript client version, and more!
