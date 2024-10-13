set shell := ["fish", "-c"]

default:
	@just --list

initdb:
	# must be run as `sudo just initdb`
	su -l postgres -c "initdb --locale=C.UTF-8 --encoding=UTF8 -D /var/lib/postgres/data --data-checksums"

create-users:
	sudo -u postgres psql --file=./00-create-users.sql

create-databases:
	sudo -u postgres psql --file=./01-create-databases.sql

alter-grants:
	sudo -u postgres psql --dbname="test" --file=./02-alter-grants.sql
	sudo -u postgres psql --dbname="app" --file=./02-alter-grants.sql
	sudo -u postgres psql --dbname="grokloc" --file=./02-alter-grants.sql

apply-schema:
	psql --username="grokloc" --dbname="app" --file=./03-schema.sql
