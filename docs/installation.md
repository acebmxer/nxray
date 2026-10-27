# Installation

[← back to the README](../README.md)

NXray runs as one Docker container. There is no published image yet, so for
now it is built from a clone of this repository on the machine that runs it.

## Requirements

- Linux with Docker Engine and the Compose plugin, Compose 2.30 or newer
  (`docker compose version`). Older Compose cannot read the `format: raw`
  setting the compose file relies on.
- Network access from that machine to the switch's management address on
  port 443, for the switch setup that arrives in a later stage.

## Steps

In a terminal on the machine that will run NXray:

1. Get the code and go into it:

       git clone https://github.com/acebmxer/nxray.git
       cd nxray

2. Make your own copies of the compose file and the settings file:

       cp docker-compose.yml.example docker-compose.yml
       cp nxray.env.example nxray.env

3. Create the hash of the password you will sign in with. This builds the
   image the first time, then asks for the password twice:

       docker compose run --rm nxray python -m app.hashpw

   It prints a line starting with `NXRAY_ADMIN_PASSWORD_HASH=$argon2id$`.

4. Open `nxray.env` in a text editor, replace the empty
   `NXRAY_ADMIN_PASSWORD_HASH=` line with the printed line, and save.

5. Start it:

       docker compose up -d

6. Open `http://<that machine's address>:8080` in a browser and sign in as
   `admin` (or the `NXRAY_ADMIN_USER` you set) with the password from step 3.

## Updating

In the `nxray` folder:

    git pull
    docker compose up -d --build

Your `docker-compose.yml`, `nxray.env` and the data volume are kept.

## If it does not start

    docker compose logs nxray

NXray refuses to start when a setting is missing or wrong, and the log says
which one and how to fix it. The most common one is an empty or mistyped
`NXRAY_ADMIN_PASSWORD_HASH`.
