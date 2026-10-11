# namecheap_updater

Namecheap has no way to update a single record. setHosts allows you to
update existing records wholesale. Get all hosts, update the record
and then write them back.

This is obviously a bit scary. Attempt to guard this a few ways:
* Archive the current zone pre-write
* Refuse to write records we don't understand
* Diff against created records to see if we messed anything up

## Configuration

Credentials from the environment:

    NAMECHEAP_API_USER    API user (usually namecheap username)
    NAMECHEAP_API_KEY     API key
    NAMECHEAP_USERNAME    account username (defaults to NAMECHEAP_API_USER)
    NAMECHEAP_CLIENT_IP   the whitelisted IP the request comes from
    NAMECHEAP_BACKUP_DIR  where to archive zone backups (default:
                          ./namecheap-backups)
## Examples

```
# set (replace) the _acme-challenge TXT record
namecheap_txt.py -d example.com -n _acme-challenge -v "token123"

# add a second TXT value alongside any existing ones
namecheap_txt.py -d example.com -n @ -v "v=spf1 -all" --append

# remove all TXT records at that name
namecheap_txt.py -d example.com -n _acme-challenge --delete

# show what would be sent without sending it
namecheap_txt.py -d example.com -n @ -v "hello" --dry-run
```

## Notes

Yeah this thing could update all kinds of records but I don't want to
do that, I just want to do TXT records.
