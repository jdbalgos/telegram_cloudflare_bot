#!/usr/bin/env python3
from telegram.ext import (Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, ChatMemberHandler, filters)
from telegram import (InlineKeyboardButton, InlineKeyboardMarkup, Update)
import yaml 
import os, sys 
import mysql.connector
import re
from datetime import datetime
import requests

run_chat_id = ''


with open('settings.yaml','r') as settings:
  api_settings_yaml = yaml.safe_load(settings)
  TOKEN = api_settings_yaml['telegram_api']['token']
  bot_backend = api_settings_yaml['telegram_api']['bot_backend']
  bot_admin = str(api_settings_yaml['telegram_api']['admin_username'])
  table_name = api_settings_yaml['mysql_data']['table_name']
  mysql_host = api_settings_yaml['mysql_data']['host']
  mysql_user = api_settings_yaml['mysql_data']['user']
  mysql_password = api_settings_yaml['mysql_data']['password']
  mysql_database = api_settings_yaml['mysql_data']['database']
  app_ver = api_settings_yaml['app_version']
  verbose = api_settings_yaml['verbose']


mydb = mysql.connector.connect(
  host=mysql_host,
  user=mysql_user,
  password=mysql_password,
  database=mysql_database
)

def yeet_checker(update):
    try:
      chat = update.message.chat
      chat_id = str(chat.id)
      record_name = 'db_' + str(chat_id)
      effective_user = str(update.effective_user.username)
      if effective_user == bot_admin:
        print('allowed')
        return True
      with open("logs/{}_allowed.logs".format(record_name), "r") as allow_file:
        allowed_username_list = allow_file.readlines()
      print(str(allowed_username_list))
      allowed_username_list = map(lambda s: s.strip(), allowed_username_list)
      if not effective_user in allowed_username_list:
        print('not allowed')
        return False
      else:
        print('allowed')
        return True
    except Exception as err:
      print("error: {}".format(err))  
      return False

  

def get_user_details(update, context):
    user = update.message.from_user
    chat_id = update.message.chat.id
    try:
        username = user.username
    except:
        username = 'none'
    try:
        first_name = user.first_name
    except:
        first_name = 'none'
    user_id = user.id
    message = """
name: {}
username: {}
user_id: {}
chat_id: {}
    """.format(first_name, username, user.id, chat_id)
    update.message.reply_text(message)
    return ConversationHandler.END
     
def start(update, context):
    update.message.reply_text(
"""
cloudflare_bot
Commands - 
/add_key       ---> import cf_key
/add_domain    ---> add domain/s 
/add_record    ---> add domain record/s (bulk)
/update_record ---> list all current record (bulk)
/list_record   ---> list all current record (bulk)
/add_user      ---> add user to use bot
/get_info      ---> get user info(to send to admin for approval)
/delete_domain ---> delete domain/s 
/list_all_domains ---> list all domains in account
"""
    )
    return ConversationHandler.END

def check_table(table_to_check):
    try:
      sql_cursor = mydb.cursor()
      tb_check = "SHOW TABLES"
      sql_cursor.execute(tb_check)
      sql_data = [item[0] for item in sql_cursor.fetchall()]
      print(sql_data)
      if table_to_check in sql_data:
        return True
      else:
        return False
    except:
      return False

def check_groupdb_exist(data_name):
    sql_cursor = mydb.cursor()
    tb_exist_q = "SELECT name FROM {}".format(table_name)
    sql_cursor.execute(tb_exist_q)
    try:
      tb_exist_data = [item[0] for item in sql_cursor.fetchall()]
      print(tb_exist_data)
    except:
      return False
    if data_name in tb_exist_data:
      return True
    else:
      return False
    
def get_group_data(name, record_name):
    sql_cursor = mydb.cursor()
    sql_query = "SELECT * FROM {} WHERE name = '{}'".format(record_name, name)
    sql_cursor.execute(sql_query)
    group_info = sql_cursor.fetchall()[0]
    group_str = ['name', 'access_key', 'email']
    mydb.commit()
    if len(group_info) == len(group_str):
      group_dict = {'success' : True}
      for i in range(len(group_info)):
        group_dict.update({group_str[i] : group_info[i]})
      return group_dict
    else:
      return {'success' : False} 
    
def create_setup(chat_id, username):
    record_name = 'db_' + str(chat_id)
    sql_cursor_create = mydb.cursor()
    sql_cursor_insert = mydb.cursor()
    if check_table(table_name):
      pass
    else:
      sql_str = "CREATE TABLE {} (name VARCHAR(50), access_key VARCHAR(50))".format(table_name)
      sql_cursor_create.execute(sql_str)
    if not check_groupdb_exist(record_name):
      create_table = "INSERT INTO {} (name, access_key) VALUES ('{}', '')".format(table_name, record_name)
      sql_cursor_insert.execute(create_table)
      with open("logs/{}_allowed.logs".format(record_name), "w") as w:
        #w.write("{}\n".format(username))
        w.write("")
      mydb.commit()
      return {'success': True}
    else:
      mydb.commit()
      return {'success': False, 'reason': 'db already exist: {}'.format(record_name)}

def delete_setup(chat_id):
    try:
      record_name = 'db_' + str(chat_id)
      SQL_query = "DELETE FROM {} WHERE name = '{}'".format(table_name, record_name)
      mysql_cursor = mydb.cursor()
      mysql_cursor.execute(SQL_query)
      mydb.commit()
      os.remove("logs/{}_allowed.logs".format(record_name))
      return {'success': True}
    except Exception as err:
      return {'success': False, 'reason': str(err)}


def add_key(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  update.message.reply_text('Enter Cloudflare Access Key')
  return ADD_ACCESS_KEY

def add_access_key(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  record_name = 'db_' + str(chat_id)
  message = update.message.text
  message = message.strip()
  verify_token = cf_token_verify(message)
  if not verify_token['success']:
    update.message.reply_text('Token Invalid: {}'.format(verify_token['reason']))
    return ConversationHandler.END
  put_access_key = update_value_str(table_name, record_name, 'access_key', message)
  if put_access_key['success']:
    update.message.reply_text('Successfully add Access Key')
    return ConversationHandler.END
  else:
    update.message.reply_text('Something went wrong: {}'.format(put_access_key['reason']))
    return ConversationHandler.END
 
def list_all_domains(update, context):
  if not yeet_checker(update):
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  record_name = 'db_' + str(chat_id)
  access_key_data = get_data_value(table_name, record_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else:
    update.message.reply_text("error getting access_key\naccess_key already added?")
    return ConversationHandler.END  
  request_all_domains = cf_list_all_domains(access_key)
  if request_all_domains['success']:
    update.message.reply_text('Domains in account:\n{}'.format('\n'.join(map(str, request_all_domains['value']))))
  else:
    update.message.reply_text("fail to get domains: {}".format(request_all_domains['reason']))
  return ConversationHandler.END

def add_domain(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  update.message.reply_text('Enter Domain Name')
  return DOMAIN_ADD

def domain_add(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  record_name = 'db_' + str(chat_id)
  access_key_data = get_data_value(table_name, record_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else:
    update.message.reply_text("error getting access_key\naccess_key already added?")
    return ConversationHandler.END 
  message = update.message.text
  domain_list = message_to_list(message)
  for domain in domain_list:
    que_domain_add = cf_domain_add(domain, access_key)
    if que_domain_add['success']:
      update.message.reply_text('Success! added {} to cloudflare!\nBe sure to add those nameservers in your registrar:\n{}'.format(domain, '\n'.join(map(str, que_domain_add['name_servers']))))
    else:
      update.message.reply_text('Fail to add {} to cloudflare!, reason: {}'.format(domain, que_domain_add['reason']))
  return ConversationHandler.END

def delete_domain(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  update.message.reply_text('Enter Domain Name')
  return DOMAIN_DELETE

def domain_delete(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  record_name = 'db_' + str(chat_id)
  access_key_data = get_data_value(table_name, record_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else:
    update.message.reply_text("error getting access_key\naccess_key already added?")
    return ConversationHandler.END 
  message = update.message.text
  domain_list = message_to_list(message)
  for domain in domain_list:
    que_domain_delete = cf_domain_delete(domain, access_key)
    if que_domain_delete['success']:
      update.message.reply_text('Success! deleted {} to cloudflare!'.format(domain))
    else:
      update.message.reply_text('Fail to delete {} to cloudflare!, reason: {}'.format(domain, que_domain_delete['reason']))
  return ConversationHandler.END

def message_to_list(message):
  message = message.strip()
  message = message.splitlines()
  message_list = [x for x in message if x]
  message_list = list(map(str.strip, message))
  return message_list
  
def record_to_list(message):
  try:
    message = message.strip()
    message = message.split('|')
    message_list = [x for x in message if x]
    message_list = list(map(str.strip, message))
    if len(message_list) != 3:
      return {'success': False, 'reason': 'parameter not match'}
    return {'domain_name': message_list[0], 'domain_type': message_list[1], 'domain_value': message_list[2], 'success': True}
  except Exception as err:
    return {'success': False, 'reason': '{}'.format(err)}
  

def add_record(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  update.message.reply_text('Enter Domain Name')
  return LOOKUP_ADD_RECORD_1

def lookup_add_record_1(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  message = update.message.text
  domain_list = message_to_list(message)
  context.user_data["domain_list_add_record"] = domain_list
  update.message.reply_text("""Enter the records to same as the format below
FQDN | RECORD TYPE | RECORD VALUE
example:
@ | A | 1.1.1.1
www | CNAME | cname.another-domain.com
test | CNAME | cname.another-domain.com""")
  return LOOKUP_ADD_RECORD_2

def lookup_add_record_2(update, context):
  if not yeet_checker(update):
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  message = update.message.text
  record_db_name = 'db_' + str(chat_id)
  domain_list = context.user_data["domain_list_add_record"]
  access_key_data = get_data_value(table_name, record_db_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else:
    update.message.reply_text("error getting access_key\naccess_key already added?")
    return ConversationHandler.END 
  record_list = message_to_list(message)
  for domain in domain_list:
    domain_name = domain
    for record in record_list:
      record_split = record_to_list(record)
      print(str(record_split))
      if record_split['success']:
        if record_split['domain_name'] == '@':
          record_name = domain
        else:
          record_name = record_split['domain_name'] + '.' + domain
        record_type = record_split['domain_type']
        record_value = record_split['domain_value']
      else:
        update.message.reply_text("error evaluating record data")
        return ConversationHandler.END
      que_cf = cf_record_add(domain_name, record_name, record_type, record_value, access_key)
      if que_cf['success']:
        update.message.reply_text("Successfully added the record {}!".format(record_name))
      else:
        update.message.reply_text("Failed to add the record {}!\nReason: {}".format(record_name, que_cf['reason']))
  return ConversationHandler.END
   

def update_record(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END

  update.message.reply_text('Enter Domain Name')
  return LOOKUP_UPDATE_RECORD_1

def lookup_update_record_1(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  message = update.message.text
  domain_list = message_to_list(message)
  context.user_data["domain_list_update_record"] = domain_list
  update.message.reply_text("""Enter the records to same as the format below
FQDN | RECORD TYPE | RECORD VALUE
example:
@ | A | 1.1.1.1
www | CNAME | cname.another-domain.com
test | CNAME | cname.another-domain.com""")
  return LOOKUP_UPDATE_RECORD_2

def lookup_update_record_2(update, context):
  if not yeet_checker(update):
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  message = update.message.text
  record_db_name = 'db_' + str(chat_id)
  domain_list = context.user_data["domain_list_update_record"]
  access_key_data = get_data_value(table_name, record_db_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else:
    update.message.reply_text("error getting access_key\naccess_key already added?")
    return ConversationHandler.END 
  record_list = message_to_list(message)
  for domain in domain_list:
    domain_name = domain
    for record in record_list:
      record_split = record_to_list(record)
      print(str(record_split))
      if record_split['success']:
        if record_split['domain_name'] == '@':
          record_name = domain
        else:
          record_name = record_split['domain_name'] + '.' + domain
        record_type = record_split['domain_type']
        record_value = record_split['domain_value']
      else:
        update.message.reply_text("error evaluating record data")
        return ConversationHandler.END
      que_cf = cf_record_update(domain_name, record_name, record_type, record_value, access_key)
      if que_cf['success']:
        update.message.reply_text("Successfully update the record {}!".format(record_name))
      else:
        update.message.reply_text("Failed to update the record {}!\nReason: {}".format(record_name, que_cf['reason']))
  return ConversationHandler.END
  

def list_record(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  update.message.reply_text('Enter Domain Name')
  return LOOKUP_LIST_RECORD_1

def lookup_list_record_1(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  chat_id = update.message.chat.id
  record_name = 'db_' + str(chat_id)
  message = update.message.text
  domain_list = message_to_list(message)
  access_key_data = get_data_value(table_name, record_name, 'access_key')
  if access_key_data['success']:
    access_key = access_key_data['value']
  else: 
    update.message.reply_text("error getting access_key\naccess_key already added?") 
    return ConversationHandler.END
  for domain in domain_list:
    domain_deets = cf_get_domain_details(domain, access_key)
    if domain_deets['success']:
      domain_zone = domain_deets['domain_zone_id']
      get_domain_records = cf_domain_record_scan(domain_zone, access_key)
      if get_domain_records['success']:
        if len(get_domain_records['value']) == 0:
          update.message.reply_text('record is empty!')
          return ConversationHandler.END
        string_to_send = "-------\n"
        for domain_records in get_domain_records['value']:
          string_to_send = string_to_send + """fqdn: {}
type: {}
value: {}
------\n""".format(domain_records['domain_record'],domain_records['record_type'],domain_records['domain_value'])
        update.message.reply_text(string_to_send)
      else:
        update.message.reply_text('Fail to retrieve domain records: {}'.format(get_domain_records['reason']))
    else:
      update.message.reply_text('Fail to retrieve domain zone id: {}'.format(domain_deets['reason']))
      return ConversationHandler.END
  return ConversationHandler.END

def add_user(update, context):
  update.message.reply_text('Enter the username of the person you want to add priveleges')
  return USER_ADD

def user_add(update, context):
  if not yeet_checker(update): 
    update.message.reply_text("user not allowed")
    return ConversationHandler.END
  try:
    chat_id = update.message.chat.id
    record_name = 'db_' + str(chat_id)
    message = update.message.text
    message = message.strip()
    message = message.strip("@")
    with open("logs/{}_allowed.logs".format(record_name), "a") as append_text:
      append_text.write("{}\n".format(message))
    update.message.reply_text('successfully add the user: {}'.format(message))
    return ConversationHandler.END
  except:
    update.message.reply_text('fail to add user')

ADD_ACCESS_KEY, DOMAIN_ADD, DOMAIN_DELETE, LOOKUP_ADD_RECORD_1, LOOKUP_ADD_RECORD_2, DOMAIN_UPDATE, LOOKUP_UPDATE_RECORD_1, LOOKUP_UPDATE_RECORD_2, LOOKUP_LIST_RECORD_1, USER_ADD = range(10)

def bot_updates(update, context):
    chat_update = update.my_chat_member.new_chat_member
    chat_id  =  update.my_chat_member.chat.id
    chat_title  =  update.my_chat_member.chat.title
    chat_type  =  update.my_chat_member.chat.type
    username = update.effective_user.username
    if chat_update.status == 'left' or  chat_update.status == 'kicked':
        deldel = delete_setup(chat_id)
        if deldel['success']:
          context.bot.send_message(chat_id=bot_backend, text='successfuly deleted data for chat: {}'.format(chat_title))
        else:
          context.bot.send_message(chat_id=bot_backend, text='error: {}'.format(deldel['reason']))
    elif chat_update.status == 'administrator' or  chat_update.status == 'member':
        if chat_update.status == 'member':
          context.bot.send_message(chat_id=chat_id, text='cloudflare_bot\nBe sure to add me in administrator so i can see the message\n/help - to see general help')
        else:
          create_set = create_setup(chat_id,username)
          if create_set['success']:
            context.bot.send_message(chat_id=bot_backend, text='successfuly created data for chat: {}'.format(chat_title))
          else: context.bot.send_message(chat_id=bot_backend, text='error: {}'.format(create_set['reason']))
    else:
        bot_status = chat_update.status
        context.bot.send_message(chat_id=bot_backend, text=str(bot_status))
    return ConversationHandler.END
        
def update_value_str(table_name, record_name, record_sbj, record_val):
    try:
      sql_cursor = mydb.cursor()
      SQL_query = "UPDATE {} SET {} = '{}' WHERE name = '{}'".format(table_name, record_sbj, record_val, record_name)
      print(SQL_query)
      sql_cursor.execute(SQL_query)
      mydb.commit()
      return {'success': True}
    except Exception as err:
      return {'success' : False, 'reason': str(err)}

def update_value_num(table_name, record_name, record_sbj, record_val):
    try:
      sql_cursor = mydb.cursor()
      SQL_query = "UPDATE {} SET {} = {} WHERE name = '{}'".format(table_name, record_sbj, record_val, record_name)
      print(SQL_query)
      sql_cursor.execute(SQL_query)
      mydb.commit()
      return {'success': True}
    except:
      return {'success' : False, 'reason': str(err)}

def get_data_value(table_name, record_name, record_sbj):
    try:
      sql_cursor = mydb.cursor()
      SQL_query = "SELECT {} FROM {} WHERE name = '{}'".format(record_sbj, table_name, record_name)
      print(SQL_query)
      sql_cursor.execute(SQL_query)
      value = [item[0] for item in sql_cursor.fetchall()][0]
      if value == '':
        return {'success': False}
      mydb.commit()
      return {'success': True, 'value': value}
    except Exception as err:
      print(str(err))
      return {'success': False}

def cf_domain_add(domain, access_key):
  try:
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    data = {"name":"{}".format(domain),"jump_start":False}
    response = requests.request("POST", url, headers=headers, json=data, timeout=5)
    response_json = response.json()
    if response_json['success']:
      return {'success': response_json['success'], 'name_servers': response_json['result']['name_servers']}
    else:
      return {'success': response_json['success'], 'reason': response_json['errors'][0]['message']}
  except Exception as err:
    return {'success': False, 'reason': str(err)}


def cf_domain_delete(domain, access_key):
  domain_name = domain
  try:
    get_zone_id = cf_get_domain_details(domain_name, access_key)
    if get_zone_id['success']:
      zone_id = get_zone_id['domain_zone_id']
    else:
      return {'success': False, 'reason': 'Unable to get zone_id'}
    url = "https://api.cloudflare.com/client/v4/zones/{}".format(zone_id)
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    data = {"name":"{}".format(domain)}
    response = requests.request("DELETE", url, headers=headers, json=data, timeout=5)
    response_json = response.json()
    if response_json['success']:
      return {'success': response_json['success']}
    else:
      return {'success': response_json['success'], 'reason': response_json['errors'][0]['message']}
  except Exception as err:
    return {'success': False, 'reason': str(err)}


def cf_token_verify(access_key):
  try:
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    response = requests.request("GET", url, headers=headers, timeout=5)
    response_json = response.json()
    print(str(response_json))
    if response_json['success']:
      return {'success': response_json['success']}
    else:
      return {'success': response_json['success'], 'reason': response_json['errors'][0]['message']}
  except Exception as err:
    return {'success': False, 'reason': str(err)}


def cf_record_add(domain_name, record_name, record_type, record_value, access_key):
  try:
    get_zone_id = cf_get_domain_details(domain_name, access_key)
    if get_zone_id['success']:
      zone_id = get_zone_id['domain_zone_id']
    else:
      return {'success': False, 'reason': 'Unable to get zone_id'}
    url = "https://api.cloudflare.com/client/v4/zones/{}/dns_records".format(zone_id)
    data = {
    "content": record_value,
    "name": record_name,
    "proxied": False,
    "type": record_type,
     }
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    response = requests.request("POST", url, headers=headers, json=data, timeout=5)
    response_json = response.json()
    if response_json['success']:
      return {'success': response_json['success']}
    else:
      return {'success': response_json['success'], 'reason': response_json['errors'][0]['message']}
  except Exception as err:
    return {'success': False, 'reason': str(err)}

def cf_record_update(domain_name, record_name, record_type, record_value, access_key):
  try:
    get_zone_id = cf_get_domain_details(domain_name, access_key)
    if get_zone_id['success']:
      zone_id = get_zone_id['domain_zone_id']
    else:
      return {'success': False, 'reason': 'Unable to get zone_id'}
    domain_scan = cf_domain_record_scan(zone_id, access_key)
    domain_identifier = None
    if domain_scan['success']:
      print(str(domain_scan))
      for domain_value in domain_scan['value']:
        print(str(domain_value))
        if domain_value['domain_record'] == record_name:
          domain_identifier = domain_value['domain_id']
          break
      if domain_identifier == None:
          return {'success': False, 'reason': 'Unable to get domain_identifier'}
    url = "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}".format(zone_id, domain_identifier)
    data = {
    "content": record_value,
    "name": record_name,
    "proxied": False,
    "type": record_type,
    }  
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    response = requests.request("PUT", url, headers=headers, json=data, timeout=5)
    response_json = response.json()
    if response_json['success']:
      return {'success': response_json['success']}
    else:
      return {'success': response_json['success'], 'reason': response_json['errors'][0]['message']}
  except Exception as err:
    return {'success': False, 'reason': str(err)}

    
  
def cf_domain_record_scan(zone_id, access_key):
  try:
    url = "https://api.cloudflare.com/client/v4/zones/{}/dns_records".format(zone_id)
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    response = requests.request("GET", url, headers=headers, timeout=5)
    response_json_page = response.json()
    get_total_pages = response_json_page['result_info']['total_pages']
    return_result = {}
    return_list = []
    for page_number in range(get_total_pages):
      page_url = 'https://api.cloudflare.com/client/v4/zones/{}/dns_records?page={}'.format(zone_id, page_number + 1)
      response = requests.request("GET", page_url, headers=headers, timeout=5)
      response_json = response.json()
      data_json = {}
      for domain_group in response_json['result']:
        return_list.append({'domain_record': domain_group['name'], 'record_type': domain_group['type'], 'domain_value': domain_group['content'], 'domain_id': domain_group['id']})
    data_json.update({'success': True, 'value': return_list}) 
    return data_json
  except Exception as err:
    return {'success': False, 'reason': '{}'.format(err)}
      
    
def cf_get_domain_details(domain, access_key):
  url = 'https://api.cloudflare.com/client/v4/zones'
  headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
  response = requests.request("GET", url, headers=headers, timeout=5)
  response_json_page = response.json()
  get_total_pages = response_json_page['result_info']['total_pages']
  return_result = {}
  for page_number in range(get_total_pages):
    page_url = 'https://api.cloudflare.com/client/v4/zones?page={}'.format(page_number + 1)
    response = requests.request("GET", page_url, headers=headers, timeout=5)
    response_json = response.json()
    for domain_group in response_json['result']:
      if domain_group['name'] == domain:
        return {'success': True, 'domain_name': domain_group['name'], 'domain_zone_id': domain_group['id'], 'domain_name_servers': domain_group['name_servers']}
  return {'success': False, 'reason': 'Not Found'}

def cf_list_all_domains(access_key):
  try:
    url = 'https://api.cloudflare.com/client/v4/zones'
    headers = { "Content-Type": "application/json", "Authorization": "Bearer {}".format(access_key) }
    response = requests.request("GET", url, headers=headers, timeout=5)
    response_json_page = response.json()
    get_total_pages = response_json_page['result_info']['total_pages']
    return_result = {}
    domains_all = []
    for page_number in range(get_total_pages):
      page_url = 'https://api.cloudflare.com/client/v4/zones?page={}'.format(page_number + 1)
      response = requests.request("GET", page_url, headers=headers, timeout=5)
      response_json = response.json()
      for domain_group in response_json['result']:
        domains_all.append(domain_group['name'])
    return {'success': True, 'value': domains_all}
  except Exception as err:
    return {'success': False, 'reason': str(err)}
      

def main():
    updater = Updater(TOKEN, use_context=True)
    updater.bot.sendMessage(chat_id=bot_backend, text='Bot Started\nApp Version: {}'.format(app_ver))
    dp = updater.dispatcher
    conv_handler = ConversationHandler(
        entry_points=[
        CommandHandler('start', start), 
        CommandHandler('help', start), 
        CommandHandler('get_info', get_user_details),
        CommandHandler('add_key', add_key),
        CommandHandler('add_domain', add_domain),
        CommandHandler('add_record', add_record),
        CommandHandler('update_record', update_record),
        CommandHandler('add_user', add_user),
        CommandHandler('list_record', list_record),
        CommandHandler('delete_domain', delete_domain),
        CommandHandler('list_all_domains', list_all_domains),
        ],
        fallbacks=[],
        allow_reentry=True,
        states={
            ADD_ACCESS_KEY: [MessageHandler(Filters.text, add_access_key)],
            DOMAIN_ADD: [MessageHandler(Filters.text, domain_add)],
            DOMAIN_DELETE: [MessageHandler(Filters.text, domain_delete)],
            LOOKUP_ADD_RECORD_1: [MessageHandler(Filters.text, lookup_add_record_1)],
            LOOKUP_ADD_RECORD_2: [MessageHandler(Filters.text, lookup_add_record_2)],
            LOOKUP_UPDATE_RECORD_1: [MessageHandler(Filters.text, lookup_update_record_1)],
            LOOKUP_UPDATE_RECORD_2: [MessageHandler(Filters.text, lookup_update_record_2)],
            LOOKUP_LIST_RECORD_1: [MessageHandler(Filters.text, lookup_list_record_1)],
            USER_ADD: [MessageHandler(Filters.text, user_add)],
        },
    )

    dp.add_handler(conv_handler)
    dp.add_handler(ChatMemberHandler(bot_updates, ChatMemberHandler.MY_CHAT_MEMBER))

    updater.start_polling(allowed_updates=Update.ALL_TYPES)
    updater.idle()


if __name__ == '__main__':
    main()
