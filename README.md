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
    SELECT (current_setting('request.headers', true)::json)->item
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

CREATE OR REPLACE FUNCTION test()
  RETURNS trigger AS
$$
BEGIN
         INSERT INTO test_table(col1,col2,col3)
         VALUES(NEW.col1,NEW.col2,current_date);
 
    RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER test_trigger
  AFTER INSERT
  ON test_table
  FOR EACH ROW
  EXECUTE PROCEDURE test();
  
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

