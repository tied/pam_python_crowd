import requests
from lxml import objectify
import syslog


headers = {'content-type': 'application/xml'}

def load_config(conf_file ='/etc/crowd.d/crowd.conf'):
  import yaml
  import sys
  try:
    cfg={}
    with open(conf_file,'r') as f:
      cfg=yaml.safe_load(f)
    auth_log("pam_crowd.py read crowd connection configuration file.")
    return cfg["user"],cfg["pass"],cfg["url"]
  except Exception as e:
    auth_log("Error:{}, conf_file:{}".format(e.msg,conf_file))
    return None,None,None

def auth_log(msg):
  syslog.openlog(facility=syslog.LOG_AUTH)
  syslog.syslog("pam_python.so %s" % msg)
  syslog.closelog()

def verify_user(username):
  r = requests.get(URL_ROOT+"user.json?username=%s"% username, auth=(AUTH_USER, AUTH_PASS))
  return r.status_code == 200 and r.json()['active']

def pam_sm_authenticate(pamh, flags, argv):
  try:
    user = pamh.get_user(None)
  except pamh.exception, e:
    return e.pam_result
  if not user:
    return pamh.PAM_USER_UNKNOWN
  try:
    resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "%s's Password:"%user))
  except pamh.exception, e:
    return e.pam_result

  try:
    data_obj = """<?xml version="1.0" encoding="UTF-8"?><password><value>%s</value></password>""" % resp.resp
    crowd_auth = requests.post(URL_ROOT+"authentication?username=%s" % user, data=data_obj, auth=(AUTH_USER,AUTH_PASS), headers=headers)
  except requests.exceptions.RequestException, e:
    return pamh.PAM_SYSTEM_ERR
  try:
    xml_content = objectify.fromstring(crowd_auth.content)
    if crowd_auth.status_code == 200:
      if xml_content.active:
        print "Welcome, %s %s" % (xml_content['first-name'], xml_content['last-name'])
        auth_log("%s %s Logged In"% (xml_content['first-name'], xml_content['last-name']))
        return pamh.PAM_SUCCESS
      else:
        return pamh.PAM_ACCT_EXPIRED 
    elif crowd_auth.status_code == 400:
      if xml_content.reason == "USER_NOT_FOUND":
        return pamh.PAM_USER_UNKNOWN
      elif xml_content.reason == "INVALID_USER_AUTHENTICATION":
        return pamh.PAM_AUTH_ERR 
      else:
        return pamh.PAM_SERVICE_ERR
    else:
      return pamh.PAM_SERVICE_ERR
  except Exception, e:
    auth_log(e.msg)
    return pamh.PAM_SYSTEM_ERR

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  return pamh.PAM_SUCCESS

if __name__ == '__main__':
  import sys
  (AUTH_USER,AUTH_PASS,URL_ROOT)=load_config()
  print verify_user(sys.argv[1])
