create table if not exists users (
-- our columns
api_secret text not null check (api_secret != ''),
api_secret_digest text unique not null check (api_secret_digest != ''),
display_name text not null check (display_name != ''),
display_name_digest text not null check (display_name_digest != ''),
email text not null check (email != ''),
email_digest text not null check (email_digest != ''),
key_version uuid not null,
org uuid not null,
password text not null check (password != ''),
-- model base
id uuid unique not null,
schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
status bigint not null check (status > 0 and status < 4),
ctime bigint check (ctime >= 1672578000 and ctime <= 32503726800),
mtime bigint check (mtime >= 1672578000 and ctime <= 32503726800),
signature uuid unique not null,
role bigint not null check (role > 0 and role < 4),
-- attributes
primary key (id));

create unique index if not exists users_email_digest_org on users (email_digest, org);

create table if not exists orgs (
-- our columns
name text unique not null check (name != ''),
owner uuid not null,
-- model base
id uuid unique not null,
schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
status bigint not null check (status > 0 and status < 4),
ctime bigint check (ctime >= 1672578000 and ctime <= 32503726800),
mtime bigint check (mtime >= 1672578000 and ctime <= 32503726800),
signature uuid unique not null,
role bigint not null check (role > 0 and role < 4),
-- attributes
primary key (id));

create table if not exists repositories (
-- our columns
name text not null check (name != ''),
org uuid not null,
owner uuid not null,
path text not null check (path != ''),
-- model base
id uuid unique not null,
schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
status bigint not null check (status > 0 and status < 4),
ctime bigint check (ctime >= 1672578000 and ctime <= 32503726800),
mtime bigint check (mtime >= 1672578000 and ctime <= 32503726800),
signature uuid unique not null,
role bigint not null check (role > 0 and role < 4),
-- attributes
primary key (id));

create unique index if not exists repositories_name_owner on repositories (name, owner);

create table if not exists audit (
-- our columns
code bigint not null check (code >= 0 and code <= 99999),
source text not null check (source != ''),
source_id uuid not null,
-- model base
id uuid unique not null,
schema_version bigint not null default 0 check (schema_version >= 0 and schema_version <= 99999),
status bigint not null default 1 check (status > 0 and status < 4),
ctime bigint check (ctime >= 1672578000 and ctime <= 32503726800),
mtime bigint check (mtime >= 1672578000 and ctime <= 32503726800),
signature uuid unique not null,
role bigint not null default 1 check (role > 0 and role < 4),
-- attributes
primary key (id));

create or replace function on_model_insert()
returns trigger
language plpgsql
as $ctime_mtime_set$
declare
_new record;
begin
_new := NEW;
_new."ctime" = floor(extract(epoch from now()));
_new."mtime" = floor(extract(epoch from now()));
_new."signature" = gen_random_uuid();
return _new;
end;
$ctime_mtime_set$;

create or replace function on_model_update()
returns trigger
language plpgsql
as $mtime_set$
declare
_new record;
begin
_new := NEW;
_new."mtime" = floor(extract(epoch from now()));
_new."signature" = gen_random_uuid();
return _new;
end;
$mtime_set$;

create trigger insert_users
before insert on users
for each row
execute procedure on_model_insert();

create trigger update_users
before update on users
for each row
execute procedure on_model_update();

create trigger insert_orgs
before insert on orgs
for each row
execute procedure on_model_insert();

create trigger update_orgs
before update on orgs
for each row
execute procedure on_model_update();

create trigger insert_repositories
before insert on repositories
for each row
execute procedure on_model_insert();

create trigger update_repositories
before update on repositories
for each row
execute procedure on_model_update();

create trigger insert_audit
before insert on audit
for each row
execute procedure on_model_insert();

create trigger update_audit
before update on audit
for each row
execute procedure on_model_update();
