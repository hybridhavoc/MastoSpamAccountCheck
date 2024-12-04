from datetime import datetime, timedelta
from collections import Counter
import itertools
import re
import json
import os
import re
import sys
import requests
import argparse
import logging

argparser=argparse.ArgumentParser()
argparser.add_argument('-c','--config', required=False, type=str, help='Optionally provide a path to a JSON file containing configuration options. If not provided, options must be supplied using command line flags.')
argparser.add_argument('--server', required=False, help="Required: The name of your server (e.g. `darkfriend.social`)")
argparser.add_argument('--access-token', action="append", required=False, help="Required: The access token can be generated at https://<server>/settings/applications")
argparser.add_argument('--max-known-id-file', required=False, default="max_known_id", help="A file to store the max known id")
argparser.add_argument('--account-limit', required=False, type=int, default=200, choices=range(1,200), help="The limit used per request to the server's accounts API" )
argparser.add_argument('--log-directory', required=False, default="logs", help="Directory to store logs")
argparser.add_argument('--logging-level', required=False, default="info", choices=['info','debug','error'], help="Loggin level.")

def check_accounts(
        server,
        access_token,
        max_known_id
):
    # Pull accounts whose ids are greater than the max known id
    ## Define some variables
    global NEW_MAX_KNOWN_ID
    global ACCOUNTS_LIMIT
    DOMAIN_LIMITS = get_server_limits(arguments.server, arguments.access_token)
    ACCOUNTS_RETURNED = ACCOUNTS_LIMIT
    REPORTS_FILED = 0
    LAST_CHECKED_ACCOUNT_ID = 999999999999999999
    # loop through getting the accounts and checking them
    while ACCOUNTS_RETURNED == ACCOUNTS_LIMIT:
        url = f"https://{server}/api/v1/admin/accounts?remote=true&limit={ACCOUNTS_LIMIT}&active=true&since_id={max_known_id}&max_id={LAST_CHECKED_ACCOUNT_ID}"
        resp = requests.get(
            url, headers={"User-Agent":user_agent(),"Authorization": f"Bearer {access_token}"}, timeout=5
        )
        if resp.status_code == 200:
            ACCOUNTS_RETURNED = len(resp.json())
            pl("info",f"Accounts retrieved. Count: {ACCOUNTS_RETURNED}")
            for record in resp.json():
                # 2022-10-28T00:00:00.000Z
                # -0001-11-30T00:00:00.000Z
                # Define user with the local data first
                user = {
                    "suspended": record["suspended"],
                    "remote_server": record["domain"],
                    "account_id": record["account"]["id"],
                    "created_at": record["account"]["created_at"],
                    "last_status_at": record["account"]["last_status_at"],
                    "followers_count": record["account"]["followers_count"],
                    "following_count": record["account"]["following_count"],
                    "statuses_count": record["account"]["statuses_count"],
                    "webfinger": record["account"]["acct"],
                    "username": record["account"]["username"],
                    "status_code": 200
                }
                LAST_CHECKED_ACCOUNT_ID = user['account_id']
                pl("debug",f"{user['account_id']} : Checking accountId")
                # Initial spam criteria check
                if (criteria_check(user)):
                    pl("debug",f"{user['account_id']} : Meets spam criteria")
                    # Check domain limits
                    if (user["remote_server"] in DOMAIN_LIMITS):
                        pl("debug",f"{user['account_id']} : Member of a limited server: {user['remote_server']}")
                    else:
                        # Check for open reports
                        if (check_account_reports(server,access_token,user['account_id']) == 0):
                            # Validate with fresh data from their remote server
                            new_user = get_account_remote(user)
                            user = new_user

                            # Check locally known statuses for bad content
                            user_bad_statuses = statuses_check(server,access_token,user)
                            if user_bad_statuses["status_code"] == 200:
                                user["bad_statuses"] = user_bad_statuses["bad_status_ids"]

                            match user["status_code"]:
                                case 410:
                                    pl("debug",f"{user['account_id']} : {user['webfinger']} : Account suspended remotely")
                                case 404:
                                    submit_report(server,access_token,user)
                                    REPORTS_FILED += 1
                                    pl("debug",f"{user['account_id']} : {user['webfinger']} : Account not found remotely, submitted report with best effort info")
                                case 401:
                                    submit_report(server,access_token,user)
                                    REPORTS_FILED += 1
                                    pl("debug",f"{user['account_id']} : {user['webfinger']} : Unauthorized at {user['remote_server']}, submitted report with best effort info")
                                case 201:
                                    # Intentional ignore
                                    pl("debug",f"{user['account_id']} : {user['webfinger']} : Account intentionally ignored")
                                case 200:
                                    # Successfully got updated data from remote server, check against spam criteria again
                                    pl("debug",f"{user['account_id']} : {user['webfinger']} : Account found remotely, rechecking spam criteria")
                                    if(criteria_check(user)):
                                        submit_report(server,access_token,user)
                                        REPORTS_FILED += 1
                                        pl("debug",f"{user['account_id']} : {user['webfinger']} : Still found to be spam")
                                    elif("bad_statuses" in user.keys()):
                                        submit_report(server,access_token,user)
                                        REPORTS_FILED += 1
                                        pl("debug",f"{user['account_id']} : {user['webfinger']} : Recheck did not match spam criteria, but multiple statuses matched against regexes")
                                    else:
                                        pl("debug",f"{user['account_id']} : {user['webfinger']} : Rechecking spam criteria resulted in no report")
                        else:
                            pl("debug",f"{user['account_id']} : Already has an open report against them.")
                else: 
                    pl("debug",f"{user['account_id']} : Did not meet spam criteria")
                if user['account_id'] > NEW_MAX_KNOWN_ID:
                    NEW_MAX_KNOWN_ID = user['account_id']
        else:
            ACCOUNTS_RETURNED = 0
            logging.error(f"Problem retrieving accounts. Status code: {resp.status_code}.")
            raise Exception(
                f"Problem retrieving accounts. Status code: {resp.status_code}. "
            )
    pl("info",f" Reports filed: {REPORTS_FILED}")

def criteria_check(
        user
):
    since = datetime.now() - timedelta(days=2)
    trusted_servers = ("flipboard.com","bsky.brid.gy")
    userCreatedAt = ''
    try: 
        userCreatedAt = datetime.strptime(user["created_at"],"%Y-%m-%dT%H:%M:%S.%fZ")
    except:
        pl("error", f"{user['account_id']} : Invalid created at value")
        return False
    
    if (
            (datetime.strptime(user["created_at"],"%Y-%m-%dT%H:%M:%S.%fZ") > since) and
            (not user["suspended"]) and
            (user["remote_server"] not in trusted_servers) and
            (user["statuses_count"] > 10) and
            (user["followers_count"] + user["following_count"] < 20) and
            (((user["followers_count"] + user["following_count"]) * 10) < user["statuses_count"])
        ):
        return True
    else:
        return False

def statuses_check(
        server,
        access_token,
        user
):
    # Setup some containers
    response = {}
    bad_status_ids = []
    bad_statuses = []
    checks = []
    
    # Pull regexes from a file named just regexes
    if os.path.exists("regexes"):
        with open("regexes", "r", encoding="utf-8") as f:
            checks = f.read().splitlines()
            pl("debug",f"{len(checks)} regexes loaded")
    else:
        pl("error",f"Regexes file could not be found")

    # Get the statuses
    get_status_lookup = f"https://{server}/api/v1/accounts/{user['account_id']}/statuses?limit=40&exclude_reblogs=true"
    get_status_resp = requests.get(get_status_lookup,headers={"User-Agent":user_agent(),"Authorization": f"Bearer {access_token}"}, timeout=5)
    if get_status_resp.status_code == 200:
        # Successfully got statuses
        statuses_json = get_status_resp.json()
        pl("debug", f"{server} : Retrieved {len(statuses_json)} statuses.")
        response["status_code"] = get_status_resp.status_code
        for status in statuses_json:
            for c in checks:
                if re.search(c, status["content"], flags=re.DOTALL|re.IGNORECASE):
                    bad_status_ids.append(status["id"])
                    bad_statuses.append(status)
        pl("debug", f"{server} : {len(bad_status_ids)} statuses found to match bad regexes.")
        if len(bad_statuses) > 0:
            response["bad_status_ids"] = bad_status_ids
            response["bad_statuses"] = bad_statuses
        else:
            response["status_code"] = 201
        return response
    else:
        # Failed to get stauses
        statuses_json = get_status_resp.json()
        pl("error", f"{server} : Failed to get account statuses for account id {user['account_id']}. {get_status_resp.status_code} : {statuses_json}")
        response["status_code"] = get_status_resp.status_code
        response["error"] = statuses_json
        return response

def get_account_remote(
        user
):
    # Trying to get the account from the remote server for validating details
    server_type = get_server_type(user["remote_server"])
    match server_type:
        case "mastodon":
            return get_account_remote__mastodon(user)
        case "iceshrimp":
            return get_account_remote__mastodon(user)
        case "firefish":
            return get_account_remote__mastodon(user)
        case "akkoma":
            return get_account_remote__pleroma(user)
        case "pleroma":
            return get_account_remote__pleroma(user)
        case "misskey":
            return get_account_remote__misskey(user)
        case "sharkey":
            return get_account_remote__misskey(user)
        case "lemmy":
            return get_account_remote__lemmy(user)
        case "peertube":
            return get_account_remote__peertube(user)
        case "threads":
            user["status_code"] = 404
            return user
        case "friendica":
            user["status_code"] = 404
            return user
        case "writefreely":
            user["status_code"] = 404
            return user
        case "plume":
            user["status_code"] = 404
            return user
        case "wordpress":
            user["status_code"] = 404
            return user
        case "pixelfed":
            return get_account_remote__pixelfed(user)
        case "Guppe Groups":
            user["status_code"] = 201
            return user
        case _:
            user["status_code"] = 404
            return user

def get_account_remote__mastodon(
        user
):
    id_lookup_url = f"https://{user['remote_server']}/api/v1/accounts/lookup?acct={user['username']}"
    id_lookup_resp = requests.get(id_lookup_url,headers={"User-Agent":user_agent()})
    if id_lookup_resp.status_code == 200:
        pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved remote accountId")
        remote_account_id = id_lookup_resp.json()["id"]
        account_lookup_url = f"https://{user['remote_server']}/api/v1/accounts/{remote_account_id}"
        account_lookup_resp = requests.get(account_lookup_url,headers={"User-Agent":user_agent()})
        if account_lookup_resp.status_code == 200:
            pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved account")
            remote_account = account_lookup_resp.json()
            user["created_at"] = remote_account["created_at"]
            user["followers_count"] = remote_account["followers_count"]
            user["following_count"] = remote_account["following_count"]
            user["statuses_count"] = remote_account["statuses_count"]
            user["status_code"] = account_lookup_resp.status_code
            return user
        else:
            pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retreiving account. Accounts Status code: {account_lookup_resp.status_code}")
            user["status_code"] = account_lookup_resp.status_code
            return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retreiving accountId. Webfinger Lookup Status code: {id_lookup_resp.status_code}")
        user["status_code"] = id_lookup_resp.status_code
        return user

def get_account_remote__pixelfed(
        user
):
    re.M
    re.I
    re_pixelfed_id = re.compile('(<profile profile-id=")([0-9]*)"')
    account_page_url = f"https://{user['remote_server']}/{user['username']}"
    account_page_resp = requests.get(account_page_url,headers={"User-Agent":user_agent()})
    if account_page_resp.status_code == 200:
        account_page = account_page_resp.text
        m = re_pixelfed_id.search(account_page)
        remote_account_id = m.group(2)
        account_lookup_url = f"https://{user['remote_server']}/api/pixelfed/v1/accounts/{remote_account_id}"
        account_lookup_resp = requests.get(account_lookup_url,headers={"User-Agent":user_agent()})
        if account_lookup_resp.status_code == 200:
            pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved account")
            remote_account = account_lookup_resp.json()
            user["created_at"] = remote_account["created_at"]
            user["followers_count"] = remote_account["followers_count"]
            user["following_count"] = remote_account["following_count"]
            user["statuses_count"] = remote_account["statuses_count"]
            user["status_code"] = account_lookup_resp.status_code
            return user
        else:
            pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retrieving account. Accounts Status code: {account_lookup_resp.status_code}")
            user["status_code"] = account_lookup_resp.status_code
            return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retrieving account page. Account Page Lookup Status code: {account_page_resp.status_code}")
        user["status_code"] = account_page_resp.status_code
        return user


    # <profile profile-id="1"

def get_account_remote__peertube(
        user
):
    account_lookup_url = f"https://{user['remote_server']}/api/v1/accounts/{user['webfinger']}"
    account_lookup_resp = requests.get(account_lookup_url,headers={"User-Agent":user_agent()})
    if account_lookup_resp.status_code == 200:
        pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved account")
        remote_account = account_lookup_resp.json()
        user["created_at"] = remote_account["createdAt"]
        user["followers_count"] = remote_account["followersCount"]
        user["following_count"] = remote_account["followingCount"]
        # Have to get the video count / statuses_count from a different endpoint
        video_count_lookup_url = f"https://{user['remote_server']}/api/v1/accounts/{user['webfinger']}/videos"
        video_count_lookup_resp = requests.get(video_count_lookup_url,headers={"User-Agent":user_agent()})
        if video_count_lookup_resp.status_code == 200:
            remote_videos = video_count_lookup_resp.json()
            user["statuses_count"] = remote_videos["total"]
        else:
            pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retrieving statuses_count. Status code: {video_count_lookup_resp.status_code}")
        return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retrieving account. Accounts Status code: {account_lookup_resp.status_code}")
        user["status_code"] = account_lookup_resp.status_code
        return user

def get_account_remote__lemmy(
        user
):
    account_lookup_url = f"https://{user['remote_server']}/api/v3/search?type_=Users&q={user['username']}"
    account_lookup_resp = requests.get(account_lookup_url,headers={"User-Agent":user_agent()})
    if account_lookup_resp.status_code == 200:
        resp = account_lookup_resp.json()
        for record in resp["users"]:
            if (record["person"]["name"] == user["username"]) and (record["person"]["local"] == True) and (record["person"]["actor_id"] == f"https://{user['remote_server']}/u/{user['username']}"):
                # Sometimes this doesn't return some keys, so you have to prepare for that
                post_score = 0
                comment_score = 0
                post_count = 0
                comment_count = 0
                try: post_score = record["counts"]["post_score"]
                except: pl("error", f"{user['account_id']} : {user['webfinger']} : Could not determine post score.")
                try: comment_score = record["counts"]["comment_score"]
                except: pl("error", f"{user['account_id']} : {user['webfinger']} : Could not determine comment score.")
                try: post_count = record["counts"]["post_count"]
                except: pl("error", f"{user['account_id']} : {user['webfinger']} : Could not determine post count.")
                try: comment_count = record["counts"]["comment_count"]
                except: pl("error", f"{user['account_id']} : {user['webfinger']} : Could not determine comment count.")

                # If it doesn't return those keys then you may not be able to trust that, so if it's reporting fewer statuses than you have locally, trust your local numbers
                user["suspended"] = record["person"]["banned"]
                user["following_count"] = 0
                if(user["followers_count"] < post_score + comment_score ): user["followers_count"] = post_score + comment_score
                if(user["statuses_count"] < post_count + comment_count): user["statuses_count"] = post_count + comment_count
                user["status_code"] = account_lookup_resp.status_code
                return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retreiving account. Account Status code: {account_lookup_resp.status_code}")
        user["status_code"] = account_lookup_resp.status_code
        return user

def get_account_remote__misskey(
        user
):
    account_lookup_data = {"limit": 1,"username": f"{user['username']}","host": f"{user['remote_server']}"}
    account_lookup_url = f"https://{user['remote_server']}/api/users/search-by-username-and-host"
    account_lookup_resp = requests.post(account_lookup_url,json=account_lookup_data,headers={"User-Agent":user_agent(),"Content-Type":"application/json"})
    if (account_lookup_resp.status_code == 200) and (len(account_lookup_resp.json()) > 0):
        pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved account")
        remote_account = account_lookup_resp.json()
        user["created_at"] = remote_account[0]["createdAt"]
        user["followers_count"] = remote_account[0]["followersCount"]
        user["following_count"] = remote_account[0]["followingCount"]
        user["statuses_count"] = remote_account[0]["notesCount"]
        user["status_code"] = account_lookup_resp.status_code
        return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retreiving account. Accounts Status code: {account_lookup_resp.status_code}")
        user["status_code"] = account_lookup_resp.status_code
        return user

def get_account_remote__pleroma(
        user
):
    account_lookup_url = f"https://{user['remote_server']}/api/v1/accounts/search?q={user['username']}&resolve=true"
    account_lookup_resp = requests.get(account_lookup_url,headers={"User-Agent":user_agent()})
    if account_lookup_resp.status_code == 200:
        pl("debug",f"{user['account_id']} : {user['webfinger']} : Retrieved account")
        remote_account = account_lookup_resp.json()[0]
        user["created_at"] = remote_account["created_at"]
        user["followers_count"] = remote_account["followers_count"]
        user["following_count"] = remote_account["following_count"]
        user["statuses_count"] = remote_account["statuses_count"]
        user["status_code"] = account_lookup_resp.status_code
        return user
    else:
        pl("error",f"{user['account_id']} : {user['webfinger']} : Problem retreiving account. Accounts Status code: {account_lookup_resp.status_code}")
        user["status_code"] = account_lookup_resp.status_code
        return user

def get_server_type(
        remote_server
):
    #Trying to determine the type of server an account is on based on the site's nodeinfo
    try:
        nodeinfo_check_resp = requests.get(f"https://{remote_server}/.well-known/nodeinfo",headers={"User-Agent":user_agent()},timeout=5)
    except requests.exceptions.RequestException as e:
        pl("error",f"{remote_server} : Nodeinfo check failed. {e}")
        return "Unknown"
    
    if nodeinfo_check_resp.status_code == 200:
        nodeinfo_link = ""
        if ((nodeinfo_check_resp.headers.get('content-type').startswith('application/json'))):
            nodeinfo_links = nodeinfo_check_resp.json()["links"]
            for link in nodeinfo_links:
                href = link["href"]
                if "nodeinfo" in href:
                    nodeinfo_link = href
                    pl("debug",f"{remote_server} : Possible nodeinfo link found : {href}")
            if nodeinfo_link == "":
                print(nodeinfo_links)
                pl("error",f"{remote_server} : Unable to get nodeinfo link on second pass")
            else:
                nodeinfo_resp = requests.get(nodeinfo_link,headers={"User-Agent":user_agent()},timeout=5)
                if nodeinfo_resp.status_code == 200:
                    nodeinfo = nodeinfo_resp.json()
                    software = nodeinfo["software"]["name"]
                    pl("info",f"{remote_server} : Software determined as {software}")
                    return software
                else:
                    pl("error",f"{remote_server} : Unable to get nodeinfo")
                    return "Unknown"
        else:
            pl("error",f"{remote_server} : Nodeinfo did not return valid json")
    else:
        pl("error",f"{remote_server} : Unable to get nodeinfo link on first pass")
        if(remote_server == "threads.net"):
            return "threads"
        else:
            return "Unknown"

def get_server_limits(
        server,
        access_token
):
    global ACCOUNTS_LIMIT
    DOMAIN_BLOCK_LIMIT = ACCOUNTS_LIMIT
    DOMAIN_BLOCKS_RETURNED = DOMAIN_BLOCK_LIMIT
    LAST_CHECKED_DOMAIN_ID = 999999999999999999
    domain_blocks = []
    while DOMAIN_BLOCKS_RETURNED == DOMAIN_BLOCK_LIMIT:
        domain_blocks_url = f"https://{server}/api/v1/admin/domain_blocks?limit={DOMAIN_BLOCK_LIMIT}&max_id={LAST_CHECKED_DOMAIN_ID}"
        domain_blocks_resp = requests.get(domain_blocks_url,headers={"User-Agent":user_agent(),"Authorization": f"Bearer {access_token}"}, timeout=5)
        if domain_blocks_resp.status_code == 200:
            resp = domain_blocks_resp.json()
            DOMAIN_BLOCKS_RETURNED = len(resp)
            for domain in resp:
                domain_blocks.append(domain["domain"])
                LAST_CHECKED_DOMAIN_ID = domain["id"]
        else:
            print("error",f"{server} : Problem getting domain blocks. Status code: {domain_blocks_resp.status_code}")
    return domain_blocks

def check_account_reports(
        server,
        access_token,
        target_account_id
):
    #Checking for unresolved reports against the account
    report_check_url = f"https://{server}/api/v1/admin/reports?target_account_id={target_account_id}"
    report_check_resp = requests.get(report_check_url, headers={"User-Agent":user_agent(),"Authorization": f"Bearer {access_token}"}, timeout=5)
    if report_check_resp.status_code == 200:
        report_count = len(report_check_resp.json())
        return report_count
    else:
        logging.error(f"{target_account_id} : Problem retrieving existing reports. Status code: {report_check_resp.status_code}")
        raise Exception(
            f"{target_account_id} : Problem retrieving existing reports. Status code: {report_check_resp.status_code}"
        )

def submit_report(
        server,
        access_token,
        user
):
    #Submitting report
    report_json = {
        "account_id": user["account_id"],
        "comment": f"Following: {user['following_count']}. Followers: {user['followers_count']}. Statuses: {user['statuses_count']}. Potential spam account, automatically determined via script. Please contact @hybridhavoc@darkfriend.social if invalid.",
        "forward": "false",
        "category": "spam"
    }
    if "bad_statuses" in user.keys():
        report_json["status_ids"] = user["bad_statuses"]
        report_json["forward"] = "true"
    report_url = f"https://{server}/api/v1/reports"
    report_resp = requests.post(report_url, headers={"User-Agent":user_agent(),"Authorization": f"Bearer {access_token}"}, json=report_json, timeout=30)
    if report_resp.status_code == 200:
        pl("info",f"{user['account_id']} : Report filed")
    else:
        pl("error",f"{user['account_id']} : Problem submitting report. Status code: {report_resp.status_code}")

def user_agent():
    return f"MastoSpamAccountCheck; +{arguments.server}"

def pl(
        level,
        message
):
    match level:
        case "debug":
            logging.debug(message)
        case "info":
            logging.info(message)
        case "error":
            logging.error(message)
        case _:
            logging.info(message)
    print(message)

if __name__ == "__main__":
    # Getting arguments
    arguments = argparser.parse_args()

    # Pulling from config file
    if(arguments.config != None):
        if os.path.exists(arguments.config):
            with open(arguments.config, "r", encoding="utf-8") as f:
                config = json.load(f)
            
            for key in config:
                setattr(arguments, key.lower().replace('-','_'), config[key])

        else:
            print(f"Config file {arguments.config} doesn't exist")
            sys.exit(1)
    
    # If no server or access token are specified, quit
    if(arguments.server == None or arguments.access_token == None):
        print("You must supply at least a server name and access token")
        sys.exit(1)

    # in case someone provided the server name as url instead, 
    setattr(arguments, 'server', re.sub(r"^(https://)?([^/]*)/?$", "\\2", arguments.server))

    # logging
    LOG_FILE_DATETIME = datetime.now().strftime("%Y-%m-%d")
    LOG_FILE = arguments.log_directory + "\\log_" + LOG_FILE_DATETIME + ".txt"
    def switch(loglevel):
        if loglevel == "info":
            return logging.INFO
        elif loglevel == "debug":
            return logging.DEBUG
        elif loglevel == "error":
            return logging.ERROR
        else:
            raise Exception(f"{arguments.loglevel} is not a valid logging level. Log level should be debug, info, or error")
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',filename=LOG_FILE, level=switch(arguments.logging_level), datefmt='%Y-%m-%d %H:%M:%S')

    # getting account call information
    ACCOUNTS_LIMIT = arguments.accounts_limit
    if os.path.exists(arguments.max_known_id_file):
        with open(arguments.max_known_id_file, "r", encoding="utf-8") as f:
            MAX_KNOWN_ID = f.read()
            NEW_MAX_KNOWN_ID = MAX_KNOWN_ID
            pl("info",f"Max known ID: {MAX_KNOWN_ID}")
    else:
        pl("error",f"Max Known ID file ({arguments.max_known_id_file}) not found")

    # Start checking accounts
    check_accounts(arguments.server, arguments.access_token, MAX_KNOWN_ID)

    # writing the max known accountId
    if not (MAX_KNOWN_ID == NEW_MAX_KNOWN_ID):
        pl("info",f" New max known ID: {NEW_MAX_KNOWN_ID}")
        #logging.info(f"New max known ID: {NEW_MAX_KNOWN_ID}")
        with open(arguments.max_known_id_file,"w", encoding="utf-8") as f:
            f.write(NEW_MAX_KNOWN_ID)
    
    # For testing
    testuser = {
            "suspended": False,
            "remote_server": "eihei.nexus",
            "account_id": "112179540169003076",
            "created_at": "",
            "followers_count": 999,
            "following_count": 999,
            "statuses_count": 999,
            "webfinger": "momus@eihei.nexus",
            "username": "momus",
            "status_code": 200
        }

    
    
    # testing = statuses_check(arguments.server, arguments.access_token, testuser)
    

    # end
    logging.info("Run complete.")
    logging.info(" ")