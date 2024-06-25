# MastoSpamAccountCheck
Script to find newly-learned-of accounts and check relatively basic thresholds to try to determine whether the account might be a spam account. This has a very high rate of false-positives, and would probably not be all that useful for a large server. This could probably be made far more sophisticated, but that is beyond my skill level and the time I wish to put into this. This is literally the first script I've written in python.

It takes a configuration file which includes:

- **access-token** : Mastodon access token, needs the following permissions: read write write:reports follow admin:read:accounts admin:read:domain_blocks admin:read:reports admin:write:reports
- **server** : Mastodon server domain, i.e. mastodon.social
- **max-known-id-file** : Text file for storing the id of the maximum known account ID. Used to determine which accounts are new to the script.
- **accounts-limit** : The number of accounts pulled per pagination. Max is 200.
- **log-directory** : Path to a directory for logs.
- **logging-level** : Specify the log level, either error, info, or debug.

This does also utilize a regex file similar to [MastoStreamWatch](https://github.com/hybridhavoc/MastoStreamWatch) but I did not include that as a configurable option.

**Note**: One thing that will need to be considered is that on the first run, the script will not have any idea what an appropriate max known account ID is. You can populate this with a recent ID by going to your Mastodon instance's admin > moderation > accounts page and looking at a recent remote account.

> https://[instance.domain]/admin/accounts?origin=remote&status=&role_ids=&order=recent&username=&display_name=&email=&ip=

Pulling up one of the recent remote accounts will leave their account ID in the URL. You can save that value into your max-known-id-file and it should start from there.

> py checky.py -c config.json

The script does require the use of [Requests](https://pypi.org/project/requests/).