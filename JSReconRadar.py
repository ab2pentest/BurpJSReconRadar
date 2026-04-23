#!/usr/bin/env python
# -*- coding:utf-8 -*-

# JSReconRadar: Burp Suite Extension for secret/token/endpoint discovery in HTTP responses
# Author: AB2 (Abdou Yelles)
# GitHub: https://github.com/ab2pentest/BurpJSReconRadar

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpListener
from burp import ITab
from burp import IHttpRequestResponse
from array import array
import re
import binascii
import base64
import xml.sax.saxutils as saxutils
import threading
import datetime
import traceback
import json

from javax.swing import JPanel, JTable, JScrollPane, JButton, JLabel
from javax.swing import SwingUtilities, BorderFactory, JFileChooser, JCheckBox
from javax.swing import JSplitPane, JTabbedPane, JTextField, RowFilter, Box
from javax.swing import JToggleButton, JDialog, JFrame, JPopupMenu, JMenuItem, JTextArea
from javax.swing.table import DefaultTableModel, TableRowSorter, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener, DocumentListener
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension
from java.awt import Toolkit
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.awt.datatransfer import StringSelection
from java.lang import Runnable, System as JavaSystem
from java.util import ArrayList


# ======= Pattern lists (split into chunks for Jython 64KB bytecode limit) =======

def _regexs_chunk_1():
    return [
    ('google_api', r'AIza[0-9A-Za-z-_]{35}'),
    ('firebase', r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    ('google_captcha', r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$'),
    ('google_oauth', r'ya29\\.[0-9A-Za-z\\-_]+'),
    ('amazon_aws_access_key_id', r'(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[0-9A-Z]{16,128}'),
    ('amazon_mws_auth_toke', r'amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('amazon_aws_url', r's3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com'),
    ('amazon_aws_url2', r'("[a-zA-Z0-9-\\.\\_]+\\.s3\\.amazonaws\\.com|s3://[a-zA-Z0-9-\\.\\_]+|s3-[a-zA-Z0-9-\\.\\_\\/]+|s3.amazonaws.com/[a-zA-Z0-9-\\.\\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\\.\\_]+)'),
    ('facebook_access_token', r'EAACEdEose0cBA[0-9A-Za-z]+'),
    ('authorization_basic', r'[Bb]asic [a-zA-Z0-9+/]{10,}={0,2}'),
    ('authorization_bearer', r'bearer [a-zA-Z0-9_\\-\\.=:_\\+\\/]{5,100}'),
    ('authorization_api', r'api[_-]?key[\s=:]+[a-zA-Z0-9_\\-]{10,100}'),
    ('mailgun_api_key', r'key-[0-9a-zA-Z]{32}'),
    ('twilio_api_key', r'SK[0-9a-fA-F]{32}'),
    ('twilio_account_sid', r'AC[a-zA-Z0-9_\\-]{32}'),
    ('twilio_app_sid', r'AP[a-zA-Z0-9_\\-]{32}'),
    ('paypal_braintree_access_token', r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}'),
    ('square_oauth_secret', r'sq0csp-[ 0-9A-Za-z\\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,43}'),
    ('square_access_token', r'sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}'),
    ('stripe_standard_api', r'sk_live_[0-9a-zA-Z]{24}'),
    ('stripe_restricted_api', r'rk_live_[0-9a-zA-Z]{24}'),
    ('github_access_token', r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*'),
    ('rsa_private_key', r'-----BEGIN RSA PRIVATE KEY-----'),
    ('ssh_dsa_private_key', r'-----BEGIN DSA PRIVATE KEY-----'),
    ('ssh_dc_private_key', r'-----BEGIN EC PRIVATE KEY-----'),
    ('pgp_private_block', r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ('json_web_token', r'ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$'),
    ('slack_token', r'\\"api_token\\":\\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\\"'),
    ('SSH_privKey', r'([-]+BEGIN [^\\s]+ PRIVATE KEY[-]+[\\s]*[^-]*[-]+END [^\\s]+ PRIVATE KEY[-]+)'),
    # Removed: Heroku API KEY UUID pattern - too broad, matches any GUID/UUID
    # ('heroku_api_key', r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ('possible_Creds', r'(?i)("password\\s*[`=:\\"]+\\s*[^\\s]+|password is\\s*[`=:\\"]*\\s*[^\\s]+|pwd\\s*[`=:\\"]*\\s*[^\\s]+|passwd\\s*[`=:\\"]+\\s*[^\\s]+)'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?server[_-]?api[_-]?key[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?partner[_-]?refresh[_-]?token[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?partner[_-]?client[_-]?secret[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?client[_-]?secret[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?api[_-]?key[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?account[_-]?refresh[_-]?token[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yt[_-]?account[_-]?client[_-]?secret[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yangshun[_-]?gh[_-]?token[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?yangshun[_-]?gh[_-]?password[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?www[_-]?googleapis[_-]?com[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)[\\"\']?wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64[\\"\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\']?[\\\\w-]+[\\"\']?'),
    ('Possible Leak', r'(?i)["\\\']?bundlesize[_-]?github[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?built[_-]?branch[_-]?deploy[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?browserstack[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?browser[_-]?stack[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?brackets[_-]?repo[_-]?oauth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?username["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?pwd["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?pass[_-]?prod["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?repo[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?release[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?pwd[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?password[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?oauth[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?oauth[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?key[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?hunter[_-]?username[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?hunter[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?github[_-]?deployment[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?argos[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?apple[_-]?id[_-]?password[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?appclientsecret[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?app[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?app[_-]?secrete[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?app[_-]?report[_-]?token[_-]?key[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?app[_-]?bucket[_-]?perm[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?apigw[_-]?access[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?apiary[_-]?api[_-]?key[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?api[_-]?secret[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?api[_-]?key[_-]?sid[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?api[_-]?key[_-]?secret[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?api[_-]?key[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?aos[_-]?sec[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?aos[_-]?key[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?ansible[_-]?vault[_-]?password[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?android[_-]?docs[_-]?deploy[_-]?token[\\"\\\']?\\s*[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?ses[_-]?access[_-]?key[_-]?id["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secrets["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?access[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?config[_-]?secretaccesskey["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?config[_-]?accesskeyid["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?access[_-]?key[_-]?id["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?access[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?access["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?author[_-]?npm[_-]?api[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?author[_-]?email[_-]?addr["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?auth0[_-]?client[_-]?secret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?auth0[_-]?api[_-]?clientsecret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?auth[_-]?token["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?assistant[_-]?iam[_-]?apikey["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifacts[_-]?secret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifacts[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifacts[_-]?bucket["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifacts[_-]?aws[_-]?access[_-]?key[_-]?id["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?artifactory[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?argos[_-]?token["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?apple[_-]?id[_-]?password["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?appclientsecret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?app[_-]?token["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?app[_-]?secrete["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?app[_-]?report[_-]?token[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?app[_-]?bucket[_-]?perm["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?apigw[_-]?access[_-]?token["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?apiary[_-]?api[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?api[_-]?secret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?api[_-]?key[_-]?sid["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?api[_-]?key[_-]?secret["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?api[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aos[_-]?sec["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aos[_-]?key["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ansible[_-]?vault[_-]?password["\\\']?\\s*[:=]\\s*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?consumerkey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?consumer[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?conekta[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?coding[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?codecov[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?codeclimate[_-]?repo[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?codacy[_-]?project[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cocoapods[_-]?trunk[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cocoapods[_-]?trunk[_-]?email["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cn[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cn[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?clu[_-]?ssh[_-]?private[_-]?key[_-]?base64["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?clu[_-]?repo[_-]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudinary[_-]?url[_-]?staging["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudinary[_-]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudflare[_-]?email["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudflare[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudflare[_-]?auth[_-]?email["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudflare[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?service[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?processed[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?parsed[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?order[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?instance["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?audited[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloudant[_-]?archived[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cloud[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?clojars[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?client[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cli[_-]?e2e[_-]?cma[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?claimr[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?claimr[_-]?superuser["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?claimr[_-]?db["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?claimr[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ci[_-]?user[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ci[_-]?server[_-]?name["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ci[_-]?registry[_-]?user["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ci[_-]?project[_-]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ci[_-]?deploy[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?chrome[_-]?refresh[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?chrome[_-]?client[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cheverny[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cf[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?certificate[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?censys[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cattle[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cattle[_-]?agent[_-]?instance[_-]?auth["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cattle[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cargo[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?cache[_-]?s3[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bx[_-]?username["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bx[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bundlesize[_-]?github[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?built[_-]?branch[_-]?deploy[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?browserstack[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?browser[_-]?stack[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?brackets[_-]?repo[_-]?oauth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?username["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?pwd["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?pass[_-]?prod["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?pass["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?auth["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bluemix[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintraykey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintray[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintray[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintray[_-]?gpg[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintray[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?bintray[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?b2[_-]?bucket["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?b2[_-]?app[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?awssecretkey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?awscn[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?awscn[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?awsaccesskeyid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?ses[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gh[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gcs[_-]?bucket[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gcr[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gcloud[_-]?service[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gcloud[_-]?project[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?gcloud[_-]?bucket[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?username[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?user[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?pw[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?login[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?ftp[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?fossa[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?flickr[_-]?api[_-]?secret[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?flickr[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?flask[_-]?secret[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firefox[_-]?secret[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firebase[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firebase[_-]?project[_-]?develop[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firebase[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firebase[_-]?api[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?firebase[_-]?api[_-]?json[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?file[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?exp[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?eureka[_-]?awssecretkey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?sonatype[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?secret[_-]?access[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?secret[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?heroku[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?env[_-]?github[_-]?oauth[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?end[_-]?user[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?encryption[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?elasticsearch[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?elastic[_-]?cloud[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dsonar[_-]?projectkey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dsonar[_-]?login[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dsonar[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dsonar[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dotenv[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digicert[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digicert[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digitalocean[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digital[_-]?ocean[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digital[_-]?ocean[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?digital[_-]?ocean[_-]?access[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?devtools[_-]?honeycomb[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?tools[_-]?honeycomb[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?to[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rake[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?login[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?admin[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?admin[_-]?login[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?rabbitmq[_-]?admin[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?postgres[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?postgres[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?mysql[_-]?password[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?mysql[_-]?host[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?api[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?credentials[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?code[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?token[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?token[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?key[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?key[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?id[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?access[_-]?credential[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?secret[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?key[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?credentials[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?auth[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?access[_-]?token[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?access[_-]?id[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?key[_-]?id[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?auth[_-]?token[_-]?key[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ]

def _regexs_chunk_2():
    return [
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?auth[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?apikey[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?token[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?id[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\'\\\']?dev[_-]?microsoft[_-]?account[_-]?apikey[_-]?key[_-]?auth[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?access[_-]?credential[\\"\\\'\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\'\\\']?[\\\\w-]+[\\"\\\'\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?netlify[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?nativeevents["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysqlsecret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysqlmasteruser["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?username["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?user["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?root[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?hostname["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mysql[_-]?database["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?my[_-]?secret[_-]?env["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?multi[_-]?workspace[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?multi[_-]?workflow[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?multi[_-]?disconnect[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?multi[_-]?connect[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?multi[_-]?bob[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?minio[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?minio[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mile[_-]?zero[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mh[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mh[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mg[_-]?public[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mg[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mapboxaccesstoken["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mapbox[_-]?aws[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mapbox[_-]?api[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mapbox[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?manifest[_-]?app[_-]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?manifest[_-]?app[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mandrill[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?managementapiaccesstoken["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?management[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?manage[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?manage[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?secret[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?pub[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?sender[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?sender[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mail[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?link[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magento[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magento[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magento[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magento[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?secret[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?magic[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?pub["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?priv["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?access[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?api[_-]?key[_-]?access[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?access[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailgun[_-]?access[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?pub["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?priv["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?access[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?apikey[_-]?access[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?access[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailchimp[_-]?access[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailer[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailer[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailer[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailer[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?mailer[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?api[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?access[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?project[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?client[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?client[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ]

def _regexs_chunk_3():
    return [
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?public[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?project[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?project[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?amazon[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?aws[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?azure[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?github[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ]

def _regexs_chunk_4():
    return [
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?gitlab[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?linkedin[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?microsoft[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?facebook[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?twitter[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?google[_-]?token[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?token[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?token[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?token[_-]?api[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?token[_-]?api[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?youtube[_-]?token[_-]?api[_-]?key[_-]?apikey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sandbox[-_]?access[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?salesforce[-_]?bulk[-_]?test[-_]?security[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?salesforce[-_]?bulk[-_]?test[-_]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sacloud[-_]?api["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sacloud[-_]?access[-_]?token[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sacloud[-_]?access[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?user[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?secret[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?secret[-_]?assets["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?secret[-_]?app[-_]?logs["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?key[-_]?assets["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?key[-_]?app[-_]?logs["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?external[-_]?3[-_]?amazonaws[-_]?com["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?bucket[-_]?name[-_]?assets["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?bucket[-_]?name[-_]?app[-_]?logs["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?access[-_]?key[-_]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?s3[-_]?access[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rubygems[-_]?auth[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rtd[-_]?store[-_]?pass["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rtd[-_]?key[-_]?pass["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?route53[-_]?access[-_]?key[-_]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ropsten[-_]?private[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rinkeby[-_]?private[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rest[-_]?api[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?repotoken["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?reporting[-_]?webdav[-_]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?reporting[-_]?webdav[-_]?pwd["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?release[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?release[-_]?gh[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?registry[-_]?secure["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?registry[-_]?pass["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?refresh[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rediscloud[-_]?url["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?redis[-_]?stunnel[-_]?urls["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?randrmusicapiaccesstoken["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?rabbitmq[-_]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?quip[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?qiita[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pypi[-_]?passowrd["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pushover[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pushover[-_]?user["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pusher[-_]?app[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pubnub[-_]?subscribe[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pubnub[-_]?secret[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pubnub[-_]?publish[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pubnub[-_]?cipher[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pubnub[-_]?auth[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?prometheus[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?private[-_]?key[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?prismic[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?private[-_]?key[-_]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?project[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?prod[-_]?deploy[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?private[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?pivotal[-_]?tracker[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?personal[-_]?access[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?paypal[-_]?client[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?paypal[-_]?client[-_]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?path[-_]?to[-_]?file["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?passwd[-_]?s3[-_]?access[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?passwd[-_]?s3[-_]?secret[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?to[-_]?jenkins["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?to[-_]?file["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?to[-_]?azure[-_]?file["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?test["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?storj["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?staging["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?stage["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?slack["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?s3["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?repo["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?rds["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?postgres["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?private["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?prod["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?preview["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?pypi["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?publish["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?qld["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?pub["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?priv["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?prod[-_]?private["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?pr["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ]

def _regexs_chunk_5():
    return [
    ('Possible Leak', r'(?i)["\\\']?password[-_]?preprod["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?preprod[-_]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?pr[-_]?live["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?p4["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?p2["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?p1["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?p[-_]?mail["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?p["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?os[-_]?aerogear["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?opensource["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?oauth["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?oauth[-_]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?o["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?myweb["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?mygit["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?my[-_]?github["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?my[-_]?git["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?migrations["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?mc4["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jwt["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jira["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?user["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?service["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?master["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?domain["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?deploy["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?admin["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins[-_]?01["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-123["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-01["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-0000["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-000["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-12345["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-0012345["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-001234["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-00123["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-0012345["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-00123["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00000["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-0000["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-000["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-0["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-0["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-00["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-001["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-002["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-003["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-004["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?password[-_]?jenkins-004["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?snoowrap[_-]?refresh[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?snoowrap[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?snoowrap[_-]?client[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?slate[_-]?user[_-]?email["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?slash[_-]?developer[_-]?space[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?slash[_-]?developer[_-]?space["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?signing[_-]?key[_-]?sid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?signing[_-]?key[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?signing[_-]?key[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?signing[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?setsecretkey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?setdstsecretkey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?setdstaccesskey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ses[_-]?secret[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?ses[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?service[_-]?account[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sentry[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sentry[_-]?secret["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sentry[_-]?endpoint["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sentry[_-]?default[_-]?org["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sentry[_-]?auth[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendwithus[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid[_-]?username["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid[_-]?user["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid[_-]?password["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sendgrid["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?selion[_-]?selenium[_-]?host["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?selion[_-]?log[_-]?level[_-]?dev["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?segment[_-]?api[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secretkey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secretaccesskey["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?key[_-]?base["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?9["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?8["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?7["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?6["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?5["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?4["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?3["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?2["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?11["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?10["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?1["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?secret[_-]?0["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sdr[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?scrutinizer[_-]?token["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sauce[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)["\\\']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id["\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*["\\\']?[\\w-]+["\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twine[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?sid[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?configuration[_-]?sid[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?api[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twilio[_-]?api[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?trex[_-]?okta[_-]?client[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?trex[_-]?client[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?secure[_-]?env[_-]?vars[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?pull[_-]?request[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?gh[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?e2e[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?com[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?branch[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?api[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?travis[_-]?access[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?token[_-]?core[_-]?java[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?thera[_-]?oss[_-]?access[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?tester[_-]?keys[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?test[_-]?test[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?test[_-]?github[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?tesco[_-]?api[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?svn[_-]?pass[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?surge[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?surge[_-]?login[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?stripe[_-]?public[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?stripe[_-]?private[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?strip[_-]?secret[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?strip[_-]?publishable[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?stormpath[_-]?api[_-]?key[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?stormpath[_-]?api[_-]?key[_-]?id[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?starship[_-]?auth[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?starship[_-]?account[_-]?sid[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?star[_-]?test[_-]?secret[_-]?access[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?star[_-]?test[_-]?location[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?star[_-]?test[_-]?bucket[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?staging[_-]?base[_-]?url[_-]?runscope[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?ssmtp[_-]?config[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sshpass[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?srcclr[_-]?api[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sqssecretkey[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sqsaccesskey[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?spring[_-]?mail[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?spotify[_-]?api[_-]?client[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?spotify[_-]?api[_-]?access[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?spaces[_-]?secret[_-]?access[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?spaces[_-]?access[_-]?key[_-]?id[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?soundcloud[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?soundcloud[_-]?client[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatypepassword[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?token[_-]?user[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?token[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?pass[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?nexus[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?gpg[_-]?passphrase[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonatype[_-]?gpg[_-]?key[_-]?name[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonar[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonar[_-]?project[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?sonar[_-]?organization[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?socrata[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?socrata[_-]?app[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?snyk[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?snyk[_-]?api[_-]?token[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?wordpress[_-]?db[_-]?user[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?wordpress[_-]?db[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?wincert[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?test[_-]?server[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?fb[_-]?password[_-]?3[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?fb[_-]?password[_-]?2[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?fb[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?basic[_-]?password[_-]?5[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?basic[_-]?password[_-]?4[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?basic[_-]?password[_-]?3[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?basic[_-]?password[_-]?2[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?widget[_-]?basic[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?watson[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?watson[_-]?device[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?watson[_-]?conversation[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?wakatime[_-]?api[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?vscetoken[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?visual[_-]?recognition[_-]?api[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?virustotal[_-]?apikey[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?vip[_-]?github[_-]?deploy[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?v[_-]?sfdc[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?v[_-]?sfdc[_-]?client[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?usertravis[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?user[_-]?assets[_-]?secret[_-]?access[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?user[_-]?assets[_-]?access[_-]?key[_-]?id[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?use[_-]?ssh[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?urban[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?urban[_-]?master[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?urban[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?unity[_-]?serial[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?unity[_-]?password[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twitteroauthaccesstoken[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twitteroauthaccesssecret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twitter[_-]?consumer[_-]?secret[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ('Possible Leak', r'(?i)[\\"\\\']?twitter[_-]?consumer[_-]?key[\\"\\\']?[^\\\\S\\r\\n]*[=:][^\\\\S\\r\\n]*[\\"\\\']?[\\w-]+[\\"\\\']?'),
    ]

def _direct_regexs_chunk_1():
    return [
        # === NEW TOKEN FORMATS (from JSAnalyzer / KeyHacks) ===
        ('github_pat_new', r'ghp_[0-9a-zA-Z]{36}'),
        ('github_pat_fine_grained', r'github_pat_[0-9a-zA-Z_]{82}'),
        ('gitlab_pat', r'glpat-[0-9a-zA-Z\-_]{20}'),
        ('telegram_bot_token', r'\d{9}:[a-zA-Z0-9_-]{35}'),
        ('linear_api_key', r'lin_api_[a-zA-Z0-9]{40}'),
        ('digitalocean_token_v1', r'dop_v1_[a-z0-9]{64}'),
        ('sendgrid_api_key', r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'),
        ('dropbox_access_token', r'sl\.[A-Za-z0-9_\-]{20,100}'),
        ('shopify_access_token', r'shpat_[0-9a-fA-F]{32}'),
        ('shopify_custom_token', r'shpca_[0-9a-fA-F]{32}'),
        ('shopify_private_token', r'shppa_[0-9a-fA-F]{32}'),
        ('new_relic_key', r'NRII-[a-zA-Z0-9]{20,}'),
        ('npm_token', r'npm_[a-zA-Z0-9]{36}'),
        ('mapbox_token', r'(?:pk|sk|tk)\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
        ('instagram_token', r'IGQVJ[a-zA-Z0-9_\-]+'),
        ('discord_bot_token', r'[MN][A-Za-z\d]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}'),
        ('discord_webhook', r'https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{17,19}/[a-zA-Z0-9_\-]{60,72}'),
        ('algolia_admin_key', r'(?i)algolia.{0,32}([a-z0-9]{32})'),
        ('algolia_app_id', r'(?i)algolia.{0,16}([A-Z0-9]{10})'),
        ('cloudflare_api_token', r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_\-]{38,42})'),
        ('cloudflare_service_key', r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._\-]{160,})'),
        ('segment_public_token', r'sgp_[A-Z0-9_\-]{60,70}'),
        ('facebook_app_id', r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})'),
        ('facebook_secret', r'(?i)(?:facebook|fb).{0,32}(?:api|app|client|consumer|secret|key).{0,32}([a-z0-9]{32})'),
        ('google_oauth2_improved', r'\bya29\.[a-z0-9_\-]{30,}\b'),
        ('http_basic_auth', r'Authorization.{0,5}Basic\s*([A-Za-z0-9+/=]+)'),
        ('jwt_token_full', r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+'),
        ('hashicorp_vault_token', r'(?:hvs|hvb|hvr)\.[a-zA-Z0-9_\-]{24,}'),
        ('twitch_oauth', r'oauth:[a-z0-9]{30}'),
        ('azure_client_secret', r'(?i)(?:azure|microsoft).{0,32}(?:secret|key|password).{0,32}([a-zA-Z0-9~_\.\-]{34,40})'),
        ('gcp_service_account', r'"type"\s*:\s*"service_account"'),
        ('openai_api_key', r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}'),
        ('openai_api_key_proj', r'sk-proj-[a-zA-Z0-9\-_]{48,}'),
        ('openai_org_id', r'org-[a-zA-Z0-9]{24,}'),
        ('anthropic_api_key', r'sk-ant-[a-zA-Z0-9_\-]{80,}'),
        ('huggingface_token', r'hf_[a-zA-Z0-9]{34}'),
        ('replicate_api_token', r'r8_[a-zA-Z0-9]{36}'),
        ('groq_api_key', r'gsk_[a-zA-Z0-9]{52}'),
        ('langsmith_api_key', r'ls__[a-f0-9]{32,}'),
        ('voyage_ai_key', r'pa-[a-zA-Z0-9]{40,}'),
        ('stability_ai_key', '(?i)stability[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-zA-Z0-9\\-_]{40,})[\\x22\\x27]'),
        ('cohere_api_key', '(?i)cohere[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-zA-Z0-9]{30,})[\\x22\\x27]'),
        ('mistral_api_key', '(?i)mistral[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-zA-Z0-9]{30,})[\\x22\\x27]'),
        ('deepseek_api_key', '(?i)deepseek[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-zA-Z0-9\\-_]{30,})[\\x22\\x27]'),
        ('together_ai_key', '(?i)together[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-zA-Z0-9]{30,})[\\x22\\x27]'),
        ('pinecone_api_key', '(?i)pinecone[a-zA-Z0-9_]*(?:key|token|secret)\\s*[=:]\\s*[\\x22\\x27]([a-f0-9\\-]{36,})[\\x22\\x27]'),
        ('azure_openai_key', '(?i)(?:azure[_-]?openai|openai[_-]?azure)[a-zA-Z0-9_]*(?:key|secret)\\s*[=:]\\s*[\\x22\\x27]([a-f0-9]{32})[\\x22\\x27]'),
        ('pypi_token', r'pypi-[a-zA-Z0-9_\-]{50,}'),

        # === GITLEAKS DISTINCTIVE-PREFIX PATTERNS ===
        # Password managers
        ('onepassword_secret_key', r'\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b'),
        ('onepassword_service_account', r'ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}'),
        # Adobe
        ('adobe_client_secret', r'\bp8e-[a-z0-9]{32}\b'),
        # Airtable
        ('airtable_pat', r'\bpat[a-zA-Z0-9]{14}\.[a-f0-9]{64}\b'),
        # Alibaba
        ('alibaba_access_key', r'\bLTAI[a-zA-Z0-9]{20}\b'),
        # Anthropic (specific formats)
        ('anthropic_admin_key', r'sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA'),
        ('anthropic_api_key_v3', r'sk-ant-api03-[a-zA-Z0-9_\-]{93}AA'),
        # Artifactory (JFrog)
        ('artifactory_api_key', r'\bAKCp[A-Za-z0-9]{69}\b'),
        ('artifactory_ref_token', r'\bcmVmd[A-Za-z0-9]{59}\b'),
        # Authress
        ('authress_service_key', r'\b(?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9\-]{10,32}\.[a-z0-9+/_=\-]{30,120}'),
        # AWS Bedrock
        ('aws_bedrock_key', r'\bABSK[A-Za-z0-9+/]{109,269}={0,2}'),
        # Azure AD
        ('azure_ad_client_secret', r'[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}'),
        # Beamer
        ('beamer_api_token', r'\bb_[a-zA-Z0-9=_\-]{44}\b'),
        # ClickHouse Cloud
        ('clickhouse_cloud_secret', r'\b4b1d[A-Za-z0-9]{38}\b'),
        # Clojars
        ('clojars_token', r'CLOJARS_[a-z0-9]{60}'),
        # Cloudflare origin CA
        ('cloudflare_origin_ca', r'\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b'),
        # Databricks
        ('databricks_token', r'\bdapi[a-f0-9]{32}(?:-\d)?\b'),
        # Defined Networking
        ('defined_networking_token', r'dnkey-[a-zA-Z0-9=_\-]{26}-[a-zA-Z0-9=_\-]{52}'),
        # DigitalOcean (additional)
        ('digitalocean_oauth', r'\bdoo_v1_[a-f0-9]{64}\b'),
        ('digitalocean_refresh', r'\bdor_v1_[a-f0-9]{64}\b'),
        # Doppler
        ('doppler_token', r'dp\.pt\.[a-zA-Z0-9]{43}'),
        # Duffel
        ('duffel_token', r'duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}'),
        # Dynatrace
        ('dynatrace_token', r'dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}'),
        # EasyPost
        ('easypost_prod_key', r'\bEZAK[a-zA-Z0-9]{54}\b'),
        ('easypost_test_key', r'\bEZTK[a-zA-Z0-9]{54}\b'),
        # Facebook
        ('facebook_page_token', r'\bEAA[MC][a-zA-Z0-9]{100,}'),
        # Flutterwave
        ('flutterwave_pub', r'FLWPUBK(?:_TEST)?-[a-f0-9]{32}-X'),
        ('flutterwave_sec', r'FLWSECK(?:_TEST)?-[a-f0-9]{32}-X'),
        ('flutterwave_enc', r'FLWSECK_TEST-[a-f0-9]{12}'),
        # Fly.io (additional formats)
        ('flyio_fm_token', r'\bfm[12][ar]?_[a-zA-Z0-9+/]{100,}={0,3}'),
        # Frame.io
        ('frameio_token', r'fio-u-[a-zA-Z0-9\-_=]{64}'),
        # GitHub (additional formats)
        ('github_user_token', r'\bghu_[0-9a-zA-Z]{36}\b'),
        ('github_server_token', r'\bghs_[0-9a-zA-Z]{36}\b'),
        ('github_oauth_token', r'\bgho_[0-9a-zA-Z]{36}\b'),
        ('github_refresh_token', r'\bghr_[0-9a-zA-Z]{36}\b'),
        # GitLab (expanded token types)
        ('gitlab_cicd_job_token', r'glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_\-]{20}'),
        ('gitlab_deploy_token', r'gldt-[0-9a-zA-Z_\-]{20}'),
        ('gitlab_feature_flag_token', r'glffct-[0-9a-zA-Z_\-]{20}'),
        ('gitlab_feed_token', r'glft-[0-9a-zA-Z_\-]{20}'),
        ('gitlab_incoming_mail', r'glimt-[0-9a-zA-Z_\-]{25}'),
        ('gitlab_k8s_agent_token', r'glagent-[0-9a-zA-Z_\-]{50}'),
        ('gitlab_oauth_app_secret', r'gloas-[0-9a-zA-Z_\-]{64}'),
        ('gitlab_pipeline_trigger', r'glptt-[0-9a-f]{40}'),
        ('gitlab_rrt', r'GR1348941[0-9a-zA-Z_\-]{20}'),
        ('gitlab_runner_token', r'glrt-[0-9a-zA-Z_\-]{20}'),
        ('gitlab_scim_token', r'glsoat-[0-9a-zA-Z_\-]{20}'),
        # Grafana
        ('grafana_api_key', r'\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}'),
        ('grafana_cloud_token', r'\bglc_[A-Za-z0-9+/]{32,400}={0,3}'),
        ('grafana_service_account', r'\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b'),
        # Harness
        ('harness_api_key', r'(?:pat|sat)\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}'),
        # Heroku v2
        ('heroku_api_key_v2', r'\bHRKU-AA[0-9a-zA-Z_\-]{58}\b'),
        # HuggingFace org
        ('huggingface_org_token', r'\bapi_org_[a-z]{34}\b'),
        # Infracost
        ('infracost_token', r'\bico-[a-zA-Z0-9]{32}\b'),
        # Intra42
        ('intra42_client_secret', r's-s4t2(?:ud|af)-[a-f0-9]{64}'),
        # MaxMind
        ('maxmind_license', r'\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b'),
        # Notion
        ('notion_token', r'\bntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}\b'),
        # Octopus Deploy
        ('octopus_api_key', r'\bAPI-[A-Z0-9]{26}\b'),
        # OpenShift
        ('openshift_user_token', r'\bsha256~[a-zA-Z0-9_\-]{43}\b'),
        # Plaid
        ('plaid_access_token', r'access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        # PlanetScale (additional)
        ('planetscale_oauth', r'\bpscale_oauth_[a-zA-Z0-9=\.\-]{32,64}\b'),
        # Postman
        ('postman_api_token', r'\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b'),
        # Prefect
        ('prefect_api_token', r'\bpnu_[a-zA-Z0-9]{36}\b'),
        # Pulumi
        ('pulumi_api_token', r'\bpul-[a-f0-9]{40}\b'),
        # ReadMe
        ('readme_api_token', r'\brdme_[a-z0-9]{70}\b'),
        # RubyGems
        ('rubygems_token', r'\brubygems_[a-f0-9]{48}\b'),
        # Scalingo
        ('scalingo_token', r'\btk-us-[a-zA-Z0-9\-]{48}\b'),
        # SendinBlue / Brevo
        ('sendinblue_token', r'\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b'),
        # Sentry (user/org tokens)
        ('sentry_user_token', r'\bsntryu_[a-f0-9]{64}\b'),
        ('sentry_org_token', r'\bsntrys_eyJ[a-zA-Z0-9+/=_\-]{100,}'),
        # SettleMint
        ('settlemint_app_token', r'\bsm_aat_[a-zA-Z0-9]{16}\b'),
        ('settlemint_pat', r'\bsm_pat_[a-zA-Z0-9]{16}\b'),
        ('settlemint_service_token', r'\bsm_sat_[a-zA-Z0-9]{16}\b'),
        # Shippo
        ('shippo_token', r'\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b'),
        # Shopify (additional)
        ('shopify_shared_secret', r'\bshpss_[a-fA-F0-9]{32}\b'),
        # Slack (expanded)
        ('slack_app_token', r'xapp-\d-[A-Z0-9]+-\d-[a-z0-9]+'),
        ('slack_bot_token', r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9\-]+'),
        ('slack_user_token', r'xox[pe]-(?:\d+-){3}[a-zA-Z0-9\-]{28,34}'),
        ('slack_config_access', r'xoxe\.xox[bp]-\d-[A-Z0-9]{163,166}'),
        ('slack_config_refresh', r'xoxe-\d-[A-Z0-9]{146}'),
        ('slack_legacy_workspace', r'xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}'),
        # Sourcegraph
        ('sourcegraph_token', r'\bsgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}\b'),
        # Sumologic
        ('sumologic_access_id', r'\bsu[a-zA-Z0-9]{12}\b'),
        # Twilio (already have SK-prefix covered)
        ('twilio_sk', r'\bSK[0-9a-fA-F]{32}\b'),
        # Typeform
        ('typeform_token', r'\btfp_[a-zA-Z0-9\-_\.=]{59}\b'),
        # Yandex
        ('yandex_iam_token', r'\bt1\.[A-Z0-9a-z_\-]+=*\.[A-Z0-9a-z_\-]{86}=*'),
        ('yandex_api_key', r'\bAQVN[A-Za-z0-9_\-]{35,38}\b'),
        ('yandex_aws_token', r'\bYC[a-zA-Z0-9_\-]{38}\b'),
        # Atlassian API token (ATATT3 prefix - recent format)
        ('atlassian_api_token', r'\bATATT3[A-Za-z0-9_\-=]{186}\b'),
        # Lob (postal API)
        ('lob_live_key', r'\blive_[a-f0-9]{35}\b'),
        ('lob_test_key', r'\btest_[a-f0-9]{35}\b'),
        ('lob_pub_key', r'\b(?:live|test)_pub_[a-f0-9]{31}\b'),
        # Mailchimp (has distinctive -us<datacenter> suffix)
        ('mailchimp_api_key', r'\b[a-f0-9]{32}-us\d{1,2}\b'),
        # Mailgun (additional key types)
        ('mailgun_pub_key', r'\bpubkey-[a-f0-9]{32}\b'),
        ('mailgun_signing_key', r'\b[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}\b'),
        # New Relic (additional distinctive prefixes)
        ('newrelic_browser_key', r'\bNRJS-[a-f0-9]{19}\b'),
        ('newrelic_user_api_key', r'\bNRAK-[A-Z0-9]{27}\b'),
        # SonarQube / SonarCloud tokens
        ('sonar_token', r'\b(?:squ_|sqp_|sqa_)[a-z0-9=_\-]{40}\b'),
        # Square (additional format)
        ('square_access_token_v2', r'\b(?:EAAA|sq0atp-)[a-zA-Z0-9_\-]{22,60}\b'),
        # Slack legacy tokens
        ('slack_legacy_token', r'xox[os]-\d+-\d+-\d+-[a-fA-F0-9]+'),
        ('slack_legacy_bot', r'xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}'),
        # Sidekiq Enterprise URL (gems.contribsys.com creds)
        ('sidekiq_sensitive_url', r'https?://[a-f0-9]{8}:[a-f0-9]{8}@(?:gems|enterprise)\.contribsys\.com'),
        # Facebook access token (modern format with pipe/URL-encoded separator)
        ('facebook_access_token_v2', r'\b\d{15,16}(?:\||%7C|%7c)[0-9a-zA-Z\-_]{27,40}\b'),
        # Stripe (extended: includes rk_test_ and _prod_ variants)
        ('stripe_key_extended', r'\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{20,99}\b'),
        # Freemius secret
        ('freemius_secret_key', r'\bsk_[a-zA-Z0-9_\-]{29}\b'),
        # Kubernetes sensitive tokens (base64 inline)
        ('k8s_service_account_token', r'\beyJhbGciOi[A-Za-z0-9+/=]{100,}\.[A-Za-z0-9+/=]{100,}\.[A-Za-z0-9+/=_\-]{43}\b'),
        # AWS access token with A3T prefix (missed in original amazon_aws_access_key_id)
        ('aws_access_token_a3t', r'\bA3T[A-Z0-9][A-Z2-7]{16}\b'),
        # AWS Bedrock short-lived (literal marker)
        ('aws_bedrock_short_lived', r'bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t'),
        # Dropbox long-lived (distinctive AAAAAAAAAA marker in the middle)
        ('dropbox_long_lived_token', r'\b[a-zA-Z0-9]{11}AAAAAAAAAA[a-zA-Z0-9\-_=]{43}\b'),
        # GitLab PAT routable (extended format: glpat-<base>.<suffix>)
        ('gitlab_pat_routable', r'\bglpat-[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b'),
        # GitLab runner token routable
        ('gitlab_runner_routable', r'\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b'),
        # GitLab session cookie
        ('gitlab_session_cookie', r'_gitlab_session=[0-9a-f]{32}'),
        # Twitter Bearer token (distinctive 22 'A' prefix)
        ('twitter_bearer_token', r'\bA{22}[a-zA-Z0-9%]{80,100}\b'),
        # PyPI upload token (specific base64 marker after pypi-)
        ('pypi_upload_token', r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_\-]{50,1000}'),
        # JWT in base64-encoded form (base64 of "eyJ" = "ZXlK")
        ('jwt_base64_encoded', r'\bZXlK[a-zA-Z0-9+/]{40,}={0,2}'),
        # GoCardless live token (distinctive live_ prefix with 40 chars)
        ('gocardless_live_token', r'\blive_[a-zA-Z0-9\-_=]{40}\b'),
        # Mollie (Mollie payments has live_/test_ prefix with 30+ chars)
        ('mollie_api_key', r'\b(?:live|test)_[a-zA-Z0-9]{30,}\b'),

        # === WEBHOOK URLS ===
        ('slack_webhook', r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}'),
        ('teams_webhook', r'https://[a-zA-Z0-9\-]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+/IncomingWebhook/[a-zA-Z0-9]+/[a-f0-9\-]+'),
        ('mattermost_webhook', r'https://[a-zA-Z0-9\-\.]+/hooks/[a-z0-9]{26}'),
        ('stripe_webhook_secret', r'whsec_[0-9a-zA-Z]{32,}'),

        # === DISTINCTIVE PREFIX TOKENS (2024-2025) ===
        ('pplx_api_key', r'pplx-[a-f0-9]{48}'),
        ('dckr_pat', r'dckr_pat_[a-zA-Z0-9_\-]{40,}'),
        ('render_api_key', r'rnd_[a-zA-Z0-9]{40,}'),
        ('railway_token', r'(?i)railway[_-]?(?:token|api[_-]?key)\s*[=:]\s*[\x22\x27]([a-f0-9]{32,})[\x22\x27]'),
        ('statsig_secret', r'secret-[a-zA-Z0-9]{40,}'),
        ('age_secret_key', r'AGE-SECRET-KEY-[A-Z0-9]{59}'),
        ('flywire_key', r'FLYW[a-zA-Z0-9_\-]{30,}'),
        ('planetscale_token', r'pscale_tkn_[a-zA-Z0-9_\-]{30,}'),
        ('planetscale_password', r'pscale_pw_[a-zA-Z0-9_\-]{30,}'),
        ('turso_auth_token', r'(?i)turso[_-]?(?:auth[_-]?token|token)\s*[=:]\s*[\x22\x27](eyJ[a-zA-Z0-9_\-\.]{80,})[\x22\x27]'),
        ('neon_api_key', r'(?i)neon[_-]?(?:api[_-]?key|token)\s*[=:]\s*[\x22\x27]([a-z0-9]{32,})[\x22\x27]'),
        ('upstash_redis_token', r'(?i)upstash[_-]?redis[_-]?(?:rest[_-]?)?token\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-=]{30,})[\x22\x27]'),

        # === OAUTH / OIDC / TENANT DISCOVERY ===
        ('openid_config_url', r'\.well-known/openid-configuration'),
        ('oauth_redirect_uri', r'(?i)(?:redirect_uri|callback_url|post_logout_redirect_uri)\s*[=:]\s*[\x22\x27](https?://[^\x22\x27]+)[\x22\x27]'),
        ('azure_tenant_id', r'(?i)(?:tenant[_-]?id|AZURE_TENANT_ID)\s*[=:]\s*[\x22\x27]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\x22\x27]'),
        ('okta_domain', r'(?i)(?:okta[_-]?domain|OKTA_DOMAIN)\s*[=:]\s*[\x22\x27]([\w\-]+\.okta\.com)[\x22\x27]'),
        ('auth0_domain', r'(?i)(?:auth0[_-]?domain|AUTH0_DOMAIN)\s*[=:]\s*[\x22\x27]([\w\-]+\.(?:us|eu|au|jp)?\.?auth0\.com)[\x22\x27]'),
        ('cognito_pool_id', r'(?:us|eu|ap|sa|ca|me|af)-(?:east|west|south|north|central|southeast|northeast)-\d:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),

        # === GRAPHQL INTROSPECTION ===
        ('graphql_introspection', r'(?:__schema|__type|introspectionQuery)'),

        # === KUBERNETES / CONTAINER INFRA ===
        ('k8s_api_internal', r'https?://kubernetes\.default(?:\.svc)?(?:\.cluster\.local)?'),
        ('etcd_endpoint', r'https?://[a-zA-Z0-9\-\.]+:2379'),

        # === SPRING BOOT / JAVA DEBUG ===
        ('spring_actuator', r'/actuator(?:/(?:env|health|info|beans|configprops|mappings|metrics|trace|heapdump|threaddump|loggers|httptrace|shutdown|jolokia|restart|pause|resume))?(?:[?\s\x22\x27]|$)'),

        # === INFRASTRUCTURE ENDPOINTS ===
        ('rds_endpoint', r'[a-zA-Z0-9\-]+\.(?:rds|db)\.amazonaws\.com'),
        ('elasticache_endpoint', r'[a-zA-Z0-9\-]+\.(?:cache|redis)\.amazonaws\.com'),
        ('documentdb_endpoint', r'[a-zA-Z0-9\-]+\.docdb\.amazonaws\.com'),
        ('cosmos_db_endpoint', r'[a-zA-Z0-9\-]+\.documents\.azure\.com'),
        ('mongo_atlas_host', r'[a-zA-Z0-9\-]+\.mongodb\.net'),

        # === MONITORING / ERROR TRACKING ===
        ('datadog_api_key', r'(?i)(?:datadog|dd)[_-]?(?:api[_-]?key|app[_-]?key)\s*[=:]\s*[\x22\x27]([a-f0-9]{32})[\x22\x27]'),
        ('rollbar_token', r'(?i)rollbar[_-]?(?:access[_-]?token|token)\s*[=:]\s*[\x22\x27]([a-f0-9]{32})[\x22\x27]'),
        ('bugsnag_api_key', r'(?i)bugsnag[_-]?(?:api[_-]?key|notifier[_-]?key)\s*[=:]\s*[\x22\x27]([a-f0-9]{32})[\x22\x27]'),
        ('logrocket_app_id', r'(?i)(?:logrocket|LogRocket)\.init\s*\(\s*[\x22\x27]([a-zA-Z0-9]{6}/[a-zA-Z0-9\-]+)[\x22\x27]'),
        ('newrelic_license', r'(?i)(?:new[_-]?relic|NR)[_-]?(?:license[_-]?key|LICENSE_KEY)\s*[=:]\s*[\x22\x27]([a-z0-9]{40}(?:NRAL)?)[\x22\x27]'),
    ]

def _direct_regexs_chunk_2():
    return [
        ('elastic_apm_token', r'(?i)(?:elastic[_-]?)?apm[_-]?(?:secret[_-]?token|server[_-]?secret)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-]{20,})[\x22\x27]'),

        # === HEADLESS CMS ===
        ('contentful_delivery_token', r'(?i)contentful[_-]?(?:delivery[_-]?token|access[_-]?token|cda[_-]?token)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-]{40,})[\x22\x27]'),
        ('contentful_space_id', r'(?i)contentful[_-]?space[_-]?id\s*[=:]\s*[\x22\x27]([a-z0-9]{12})[\x22\x27]'),
        ('sanity_project_id', r'(?i)sanity[_-]?project[_-]?id\s*[=:]\s*[\x22\x27]([a-z0-9]{8})[\x22\x27]'),
        ('storyblok_token', r'(?i)storyblok[_-]?(?:token|api[_-]?key)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{22,})[\x22\x27]'),
        ('prismic_token', r'(?i)prismic[_-]?(?:access[_-]?token|token)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-\.]{40,})[\x22\x27]'),

        # === PAYMENT PLATFORMS ===
        ('razorpay_key_id', r'rzp_(?:live|test)_[a-zA-Z0-9]{14,}'),
        ('flutterwave_key', r'FL(?:WPK|WSECK|WPUBK)_(?:TEST|LIVE)-[a-f0-9]{32,}'),
        ('paystack_key', r'(?:pk|sk)_(?:live|test)_[a-f0-9]{40,}'),
        ('mollie_api_key', r'(?:live|test)_[a-zA-Z0-9]{30,}'),
        ('paddle_api_key', r'(?i)paddle[_-]?(?:api[_-]?key|vendor[_-]?auth[_-]?code)\s*[=:]\s*[\x22\x27]([a-f0-9]{32,})[\x22\x27]'),
        ('lemonsqueezy_api_key', r'(?i)lemon[_-]?squeezy[_-]?(?:api[_-]?key|token)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{40,})[\x22\x27]'),

        # === MESSAGING / COMMUNICATION ===
        ('vonage_api_key', r'(?i)(?:vonage|nexmo)[_-]?(?:api[_-]?key|api[_-]?secret)\s*[=:]\s*[\x22\x27]([a-f0-9]{8,16})[\x22\x27]'),
        ('messagebird_key', r'(?i)messagebird[_-]?(?:api[_-]?key|access[_-]?key)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{25})[\x22\x27]'),
        ('pusher_key', r'(?i)(?:pusher[_-]?(?:key|app[_-]?key))\s*[=:]\s*[\x22\x27]([a-f0-9]{20})[\x22\x27]'),
        ('pusher_secret', r'(?i)pusher[_-]?(?:secret|app[_-]?secret)\s*[=:]\s*[\x22\x27]([a-f0-9]{20})[\x22\x27]'),
        ('ably_api_key', r'[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{5,}:[a-zA-Z0-9_\-+/]{10,}'),

        # === MAP / GEO SERVICES ===
        ('here_api_key', r'(?i)(?:here|HERE)[_-]?(?:api[_-]?key|app[_-]?id)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-]{40,})[\x22\x27]'),
        ('tomtom_api_key', r'(?i)(?:tomtom|TOMTOM)[_-]?(?:api[_-]?key|key)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{32})[\x22\x27]'),

        # === FEATURE FLAGS ===
        ('splitio_key', r'(?i)(?:split[_-]?io|SPLIT)[_-]?(?:api[_-]?key|sdk[_-]?key|auth[_-]?token)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{32,})[\x22\x27]'),
        ('flagsmith_key', r'(?i)flagsmith[_-]?(?:environment[_-]?key|api[_-]?key)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{32,})[\x22\x27]'),
        ('posthog_api_key', r'phc_[a-zA-Z0-9]{40,}'),
        ('posthog_project_key', r'(?i)posthog[_-]?(?:api[_-]?key|project[_-]?key)\s*[=:]\s*[\x22\x27](phc_[a-zA-Z0-9]{40,})[\x22\x27]'),

        # === HOSTING / DEPLOYMENT ===
        ('vercel_token', r'(?i)vercel[_-]?(?:token|api[_-]?token)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{24})[\x22\x27]'),
        ('fly_io_token', r'(?i)fly[_-]?(?:api[_-]?token|token)\s*[=:]\s*[\x22\x27](fo1_[a-zA-Z0-9_\-]{40,})[\x22\x27]'),
        ('convex_deploy_key', r'(?i)convex[_-]?(?:deploy[_-]?key|admin[_-]?key)\s*[=:]\s*[\x22\x27](prod:|dev:)[a-zA-Z0-9|_\-]{20,}[\x22\x27]'),

        # === SEARCH / DATABASE SAAS ===
        ('typesense_api_key', r'(?i)typesense[_-]?(?:api[_-]?key|search[_-]?only[_-]?key)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{32,})[\x22\x27]'),
        ('meilisearch_key', r'(?i)meili[_-]?(?:search[_-]?)?(?:master[_-]?key|api[_-]?key)\s*[=:]\s*[\x22\x27]([a-f0-9]{32,})[\x22\x27]'),
        ('elasticsearch_api_key', r'(?i)elastic[_-]?(?:search[_-]?)?(?:api[_-]?key|cloud[_-]?id)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9_\-=]{30,})[\x22\x27]'),

        # === DOM XSS SINKS (client-side injection points) ===
        ('xss_innerhtml', '\\.innerHTML\\s*='),
        ('xss_outerhtml', '\\.outerHTML\\s*='),
        ('xss_document_write', 'document\\.write(?:ln)?\\s*\\('),
        ('xss_eval', '(?:^|[^a-zA-Z0-9_])eval\\s*\\('),
        ('xss_settimeout_str', 'setTimeout\\s*\\(\\s*[\\x22\\x27]'),
        ('xss_setinterval_str', 'setInterval\\s*\\(\\s*[\\x22\\x27]'),
        ('xss_jquery_html', '\\.html\\s*\\([^)]+\\)'),

        # === POSTMESSAGE HANDLERS (XSS via cross-origin messaging) ===
        ('postmessage_listener', 'addEventListener\\s*\\([\\x22\\x27]message[\\x22\\x27]'),
        ('postmessage_send', '\\.postMessage\\s*\\('),

        # === OPEN REDIRECT PARAMETERS ===
        ('open_redirect_param', '(?i)[?&](?:redirect|redirect_url|redirect_uri|return|return_to|return_url|next|next_url|url|goto|target|dest|destination|continue|callback_url|forward|redir|out|view|login_url|image_url|rurl)\\s*='),

        # === PROTOTYPE POLLUTION ===
        ('proto_pollution', '__proto__'),
        ('constructor_proto', 'constructor\\s*\\.\\s*prototype'),
        ('object_assign_merge', '(?:Object\\.assign|_\\.merge|_\\.extend|_\\.defaults|jQuery\\.extend)\\s*\\('),

        # === JSONP CALLBACKS ===
        ('jsonp_callback', '(?i)[?&](?:callback|jsonp|cb|jsonpcallback)\\s*='),

        # === CREDENTIALS IN URLS ===
        ('credentials_in_url', 'https?://[a-zA-Z0-9._%+\\-]+:.+@[a-zA-Z0-9][a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}'),
        # Token/key embedded in URL without password (e.g. https://key@host.io/path)
        ('token_in_url', '(?:https?|ftp|amqp|redis|mongodb|postgresql|mysql)://[a-fA-F0-9]{16,}@[a-zA-Z0-9][a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}'),

        # === HIDDEN/DEBUG PARAMETERS ===
        ('debug_param', '(?i)[?&](?:debug|test|testing|admin|verbose|trace|dev|staging|internal|backdoor|secret)\\s*='),

        # === TODO/FIXME NEAR SECRETS ===
        ('todo_secret', '(?i)(?://|/\\*|#)\\s*(?:TODO|FIXME|HACK|XXX|BUG|TEMP)\\s*:?.*(?:password|secret|key|token|credential|api_key)'),

        # === DATABASE CONNECTION STRINGS ===
        ('mongodb_uri', 'mongodb(?:\\+srv)?://[^\\s<>\\x22\\x27]+'),
        ('postgresql_uri', 'postgres(?:ql)?://[^\\s<>\\x22\\x27]+'),
        ('mysql_uri', 'mysql://[a-z0-9._%+\\-]+:[^\\s:@]+@[^\\s<>\\x22\\x27]+'),
        ('redis_uri', 'redis(?:s)?://[^\\s<>\\x22\\x27]+'),
        ('amqp_uri', 'amqp(?:s)?://[^\\s<>\\x22\\x27]+'),

        # === CLOUD STORAGE & INFRASTRUCTURE URLs (from JS Miner + JSAnalyzer) ===
        ('azure_blob_storage', r"https?://[a-zA-Z0-9.\-]+\.blob\.core\.windows\.net[^\s<>\"']*"),
        ('azure_onedrive', r"https?://[a-zA-Z0-9.\-]+\.onedrive\.live\.com[^\s<>\"']*"),
        ('google_cloud_storage', r"https?://storage\.googleapis\.com/[^\s<>\"']+"),
        ('google_cloud_storage2', r"https?://[a-zA-Z0-9.\-]+\.storage\.googleapis\.com[^\s<>\"']*"),
        ('firebase_db_url', r"https?://[a-z0-9\-]+\.firebaseio\.com[^\s<>\"']*"),
        ('cloudfront_url', r"https?://[a-zA-Z0-9.\-]+\.cloudfront\.net[^\s<>\"']*"),
        ('digitalocean_spaces', r"https?://[a-zA-Z0-9.\-]+\.digitaloceanspaces\.com[^\s<>\"']*"),
        ('oracle_cloud', r"https?://[a-zA-Z0-9.\-]+\.oraclecloud\.com[^\s<>\"']*"),
        ('alibaba_cloud', r"https?://[a-zA-Z0-9.\-]+\.aliyuncs\.com[^\s<>\"']*"),
        ('rackspace_cdn', r"https?://[a-zA-Z0-9.\-]+\.rackcdn\.com[^\s<>\"']*"),
        ('websocket_url', r"wss?://[^\s<>\"']{10,}"),
        ('sftp_url', r"sftp://[^\s<>\"']{10,}"),
        ('ftp_url', r"ftp://[^\s<>\"']{10,}"),

        # === API ENDPOINTS (from JSAnalyzer + JS Miner) ===
        ('api_endpoint', '[\\x22\\x27](/api/v?\\d*/[a-zA-Z0-9/_\\-]{2,})[\\x22\\x27]'),
        ('rest_endpoint', '[\\x22\\x27](/rest/[a-zA-Z0-9/_\\-]{2,})[\\x22\\x27]'),
        ('graphql_endpoint', '[\\x22\\x27](/graphql[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('oauth_endpoint', '[\\x22\\x27](/oauth[0-9]*/[a-zA-Z0-9/_\\-]+)[\\x22\\x27]'),
        ('auth_endpoint', '[\\x22\\x27](/auth[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('admin_endpoint', '[\\x22\\x27](/admin[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('internal_endpoint', '[\\x22\\x27](/internal[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('debug_endpoint', '[\\x22\\x27](/debug[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('config_endpoint', '[\\x22\\x27](/config[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('upload_endpoint', '[\\x22\\x27](/upload[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('wellknown_endpoint', '[\\x22\\x27](/\\.well-known/[a-zA-Z0-9/_\\-]+)[\\x22\\x27]'),
        ('idp_endpoint', '[\\x22\\x27](/idp/[a-zA-Z0-9/_\\-]+)[\\x22\\x27]'),
        # JS Miner style: .get("/path"), .post("/path"), etc.
        # Require value to start with / or http to avoid matching config getters
        ('js_get_endpoint', '\\.(?:\\$)?get\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]\\)'),
        ('js_post_endpoint', '\\.(?:\\$)?post\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]\\)'),
        ('js_put_endpoint', '\\.(?:\\$)?put\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]\\)'),
        ('js_delete_endpoint', '\\.(?:\\$)?delete\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]\\)'),
        ('js_patch_endpoint', '\\.(?:\\$)?patch\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]\\)'),

        # === JS URL EXTRACTION (from jsluice) ===
        # fetch("url") / fetch('url')
        ('js_fetch_url', 'fetch\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # window.open("url") / open("url")
        ('js_window_open', '(?:window\\.)?open\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # location.replace("url") / location.assign("url")
        ('js_location_nav', 'location\\.(?:replace|assign|href\\s*=)\\s*[\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # XMLHttpRequest: xhr.open("GET", "/api/...")
        ('js_xhr_open', '\\.open\\([\\x22\\x27](?:GET|POST|PUT|DELETE|PATCH|OPTIONS)[\\x22\\x27]\\s*,\\s*[\\x22\\x27]([^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # $.ajax({url: "/api/..."}) or $.ajax("/api/...")
        ('js_ajax_url', '\\.ajax\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        ('js_ajax_url_prop', '\\.ajax\\(\\{[^}]*url\\s*:\\s*[\\x22\\x27]([^\\x22\\x27]+)[\\x22\\x27]'),
        # .href = "url", .src = "url"
        ('js_href_assign', '\\.(?:href|src|action)\\s*=\\s*[\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # axios("/url") / axios.get("/url") etc.
        ('js_axios_url', 'axios(?:\\.(?:get|post|put|delete|patch|head|options))?\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),
        # request("url") / superagent.get("url")
        ('js_request_url', '(?:request|superagent)\\.?(?:get|post|put|del|delete|patch)?\\([\\x22\\x27]((?:/|https?://)[^\\s\\x22\\x27]+)[\\x22\\x27]'),

        # === FIREBASE FULL CONFIG (from jsluice - high confidence) ===
        # Detects Firebase config objects with apiKey + authDomain + projectId + storageBucket
        ('firebase_config_apikey', '(?i)apiKey\\s*:\\s*[\\x22\\x27](AIza[a-zA-Z0-9_\\-]{30,})[\\x22\\x27]'),
        ('firebase_config_domain', '(?i)authDomain\\s*:\\s*[\\x22\\x27]([a-zA-Z0-9\\-]+\\.firebaseapp\\.com)[\\x22\\x27]'),
        ('firebase_config_project', '(?i)projectId\\s*:\\s*[\\x22\\x27]([a-zA-Z0-9\\-]{4,})[\\x22\\x27]'),
        ('firebase_config_bucket', '(?i)storageBucket\\s*:\\s*[\\x22\\x27]([a-zA-Z0-9\\-]+\\.appspot\\.com)[\\x22\\x27]'),
        ('firebase_config_messaging', '(?i)messagingSenderId\\s*:\\s*[\\x22\\x27](\\d{10,})[\\x22\\x27]'),

        # === AWS SECRET KEY PAIR (from jsluice - elevated severity) ===
        ('aws_secret_access_key', '(?i)(?:aws_?)?secret_?(?:access_?)?key\\s*[=:\\x22\\x27]\\s*[\\x22\\x27]?([A-Za-z0-9/+=]{40})[\\x22\\x27]?'),

        # === EMAIL ADDRESSES ===
        ('email_address', r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}'),

        # === SENSITIVE FILE REFERENCES ===
        ('sensitive_file_ref', '[\\x22\\x27]([a-zA-Z0-9_/.\\-]+\\.(?:sql|csv|env|bak|backup|old|key|pem|crt|cer|p12|pfx|jks|keystore|conf|cfg|ini|log|secret|credentials|htpasswd|pgpass|shadow|kdbx))[\\x22\\x27]'),

        # === JS CONFIG / OBJECT SECRET PATTERNS ===
        # Catches key:value and key:"value" patterns in JS objects where the
        # key name suggests a secret (apiKey, clientSecret, accessToken, etc.)
        # Matches: someKey:"value", some_key:'value', someKey:value
        ('js_config_secret', '(?i)[,{\\s]([a-zA-Z0-9_]*(?:secret|token|password|passwd|apikey|api_key|access_key|private_key|client_key|client_secret|auth_key|auth_token|session_key|session_token|encryption_key|decrypt_key)[a-zA-Z0-9_]*)\\s*[=:]\\s*[\\x22\\x27]([^\\x22\\x27]{8,})[\\x22\\x27]'),
        # Removed js_config_secret2 (unquoted values) - too noisy, catches error
        # constants like INVALID_TOKEN, STRONG_FORM_PASSWORD, code fragments etc.
        # The quoted version (js_config_secret) is kept and sufficient.

        # Connection strings (redis://, amqp://, etc. in JS config)
        ('js_config_connection_string', '(?i)[,{\\s]([a-zA-Z0-9_]*(?:connection_?string|conn_?str|database_?url|db_?url|redis_?url|cache_?url|broker_?url|queue_?url)[a-zA-Z0-9_]*)\\s*[=:]\\s*[\\x22\\x27]([^\\x22\\x27]{8,})[\\x22\\x27]'),

        # DSN patterns (Sentry, error tracking, etc.)
        ('js_config_dsn', '(?i)[,{\\s]([a-zA-Z0-9_]*(?:dsn|sentry_?dsn|error_?dsn|tracking_?dsn)[a-zA-Z0-9_]*)\\s*[=:]\\s*[\\x22\\x27]([^\\x22\\x27]{8,})[\\x22\\x27]'),
        # Sentry DSN URL format: https://<key>@<org>.ingest.sentry.io/<project>
        ('sentry_dsn_url', r'https?://[a-f0-9]{32}@[a-zA-Z0-9\-]+\.(?:ingest\.)?sentry\.io/\d+'),

        # Specific service keys found in JS configs
        ('adyen_client_key', '(?i)adyen[a-zA-Z0-9_]*key\\s*[=:]\\s*[\\x22\\x27]?([a-zA-Z0-9_\\-]{20,})[\\x22\\x27]?'),
        ('stripe_publishable_key', r'pk_(?:live|test)_[0-9a-zA-Z]{24,}'),
        ('stripe_secret_key', r'sk_(?:live|test)_[0-9a-zA-Z]{24,}'),
        ('intercom_app_id', r'(?i)(?:intercom[_-]?app[_-]?id|INTERCOM_APP_ID)\s*[=:]\s*[\x22\x27]([a-zA-Z0-9]{6,})[\x22\x27]'),
        ('launchdarkly_client_id', r'(?i)(?:launch[_-]?darkly[_-]?(?:client[_-]?id|sdk[_-]?key)|LAUNCH_DARKLY_CLIENT_ID)\s*[=:]\s*[\x22\x27]([a-f0-9]{24,})[\x22\x27]'),
        ('meta_pixel_id', r'(?i)(?:meta[_-]?pixel[_-]?id|facebook[_-]?pixel[_-]?id|fb[_-]?pixel[_-]?id|fbq\s*\(\s*[\x22\x27]init[\x22\x27]\s*,\s*[\x22\x27])(\d{12,20})'),
        ('mixpanel_token', r'(?i)(?:mixpanel[_-]?token|MIXPANEL_TOKEN)\s*[=:]\s*[\x22\x27]([a-f0-9]{32})[\x22\x27]'),
        ('segment_write_key', r'(?i)(?:segment[_-]?(?:write[_-]?key|api[_-]?key)|analytics\.load)\s*[=:(]\s*[\x22\x27]([a-zA-Z0-9]{20,})[\x22\x27]'),
        ('amplitude_api_key', r'(?i)(?:amplitude[_-]?(?:api[_-]?key|key)|AMPLITUDE_API_KEY)\s*[=:]\s*[\x22\x27]([a-f0-9]{32})[\x22\x27]'),
        ('hotjar_id', r'(?i)(?:hotjar[_-]?(?:id|site[_-]?id)|HOTJAR_ID|hj\s*\(\s*[\x22\x27]init[\x22\x27]\s*,\s*)(\d{6,8})'),
        ('google_tag_manager', r'GTM-[A-Z0-9]{6,8}'),
        ('google_analytics', r'(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,12})'),

        # Generic: any camelCase or snake_case key name ending in Key/Secret/Token/Password
        # with a quoted string value of 10+ chars
        ('js_generic_key', '(?i)[,{\\s]([a-zA-Z]{2,30}(?:Key|Secret|Token|Password|Credential|Passphrase))\\s*:\\s*[\\x22\\x27]([^\\x22\\x27]{10,})[\\x22\\x27]'),

        # Generic: snake_case versions
        ('js_generic_snake_key', '(?i)[,{\\s]([a-zA-Z0-9]+(?:_key|_secret|_token|_password|_credential|_passphrase|_api_key|_client_id|_client_secret|_app_id))\\s*[=:]\\s*[\\x22\\x27]([^\\x22\\x27]{8,})[\\x22\\x27]'),

        # === ESCAPED JSON-IN-JS PATTERNS ===
        # Catches \"key\":\"value\" inside JS strings (JSON embedded in JS)
        # r'\\\\\"' matches literal backslash + quote in the content
        ('json_escaped_key', r'\\\\\"([a-zA-Z_]{2,40}(?:Key|key|Secret|secret|Token|token|Password|password|Credential|credential))\\\\\":\\\\\"([^\\\\\"]{8,}?)\\\\\"'),
        ('json_escaped_url', r'\\\\\"([a-zA-Z_]{2,40}(?:Url|url|URL|Uri|uri|URI|Endpoint|endpoint|Host|host|Domain|domain))\\\\\":\\\\\"(https?://[^\\\\\"]+?)\\\\\"'),
        ('json_escaped_dsn', r'\\\\\"([a-zA-Z_]{2,40}(?:Dsn|dsn|DSN|ConnectionString|connectionString|connection_string))\\\\\":\\\\\"([^\\\\\"]{8,}?)\\\\\"'),

        # === INTERNAL IP ADDRESSES (information disclosure) ===
        ('internal_ip_10', r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
        ('internal_ip_172', r'\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'),
        ('internal_ip_192', r'\b(192\.168\.\d{1,3}\.\d{1,3})\b'),
        ('internal_ip_127', r'\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
        ('ipv6_local', r'(?i)\b(fe80:[0-9a-f:]+)\b'),
        ('ipv6_loopback', r'(?i)\b(::1)\b'),

        # === EXTERNAL IP ADDRESSES (hardcoded servers, APIs, infrastructure) ===
        # Strict: each octet 0-255, no leading zeros, excludes internal/reserved ranges
        ('external_ip', r'(?<![.\d])(?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?!127\.)(?!0\.)(?!255\.)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?![.\d])'),

        # === HARDCODED INTERNAL / DEV / STAGING DOMAINS ===
        ('staging_domain', r"https?://[a-zA-Z0-9.\-]*(?:staging|stage)[a-zA-Z0-9.\-]*\.[a-zA-Z]{2,10}[^\s<>\"']*"),
        ('dev_domain', r"https?://[a-zA-Z0-9.\-]*(?:\.dev\.|\.development\.|-dev\.|-development\.)[a-zA-Z0-9.\-]*[^\s<>\"']*"),
        ('internal_domain', r"https?://[a-zA-Z0-9.\-]*(?:\.internal\.|\.local\.|\.intranet\.|-internal\.)[a-zA-Z0-9.\-]*[^\s<>\"']*"),
        ('test_domain', r"https?://[a-zA-Z0-9.\-]*(?:\.test\.|\.testing\.|-test\.|-testing\.)[a-zA-Z0-9.\-]*[^\s<>\"']*"),
        ('sandbox_domain', r"https?://[a-zA-Z0-9.\-]*(?:\.sandbox\.|-sandbox\.)[a-zA-Z0-9.\-]*[^\s<>\"']*"),
        ('preprod_domain', r"https?://[a-zA-Z0-9.\-]*(?:\.preprod\.|-preprod\.|\.pre-prod\.|-pre-prod\.)[a-zA-Z0-9.\-]*[^\s<>\"']*"),
        ('localhost_url', r"https?://localhost(?::\d{2,5})?[^\s<>\"']*"),
        ('ip_url', r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?[^\s<>\"']*"),

        # === CORS MISCONFIGURATION ===
        ('cors_wildcard', r'Access-Control-Allow-Origin:\s*\*'),
        ('cors_null', r'Access-Control-Allow-Origin:\s*null'),
        ('cors_credentials_true', r'Access-Control-Allow-Credentials:\s*true'),

        # === SOURCE MAPS (source code disclosure) ===
        ('source_map_url', r'//[#@]\s*sourceMappingURL\s*=\s*([^\s]+\.map)'),
        ('source_map_url2', r'//[#@]\s*sourceMappingURL\s*=\s*data:application/json;[^\s]+'),
        ('source_map_header', r'SourceMap:\s*([^\s]+\.map)'),
        ('source_map_header2', r'X-SourceMap:\s*([^\s]+\.map)'),

        # === ERROR STACK TRACES / PATH DISCLOSURE ===
        ('stack_trace_node', r'at\s+[a-zA-Z0-9_.<>]+\s+\((/[a-zA-Z0-9_.\-/]+\.(?:js|ts|mjs|cjs)):\d+:\d+\)'),
        ('stack_trace_python', r'File\s+"(/[a-zA-Z0-9_.\-/]+\.py)",\s+line\s+\d+'),
        ('stack_trace_java', r'at\s+[a-zA-Z0-9_.]+\([a-zA-Z0-9_]+\.java:\d+\)'),
        ('stack_trace_csharp', r'at\s+[a-zA-Z0-9_.]+\s+in\s+([a-zA-Z]:\\[^\s:]+\.cs):line\s+\d+'),
        ('stack_trace_php', r'(?:in\s+|Stack trace:.*?)(/[a-zA-Z0-9_.\-/]+\.php)(?:\s+on\s+line\s+|\:)\d+'),
        ('stack_trace_ruby', r'(/[a-zA-Z0-9_.\-/]+\.rb):\d+:in\s+'),
        ('windows_path', r'[A-Za-z]:\\(?:Users|Windows|Program Files|inetpub|wwwroot|home|var|app)[\\a-zA-Z0-9_.\-\s]+'),
        ('unix_path_disclosure', r'(?:/home/|/var/www/|/opt/|/srv/|/usr/local/|/app/|/root/)[a-zA-Z0-9_.\-/]{5,}'),
        ('sql_error', r'(?i)(?:SQL syntax|mysql_fetch|ORA-\d{5}|PG::Error|SQLite3::SQLException|SQLSTATE\[)'),
        ('debug_mode', r'(?i)(?:Traceback \(most recent call last\)|Debug mode: ON|DJANGO_SETTINGS_MODULE|Laravel.*?stack trace)'),

        # === ENCODED DATA DETECTION ===
        # Base64 (min 20 chars, looks like base64, not a common word)
        # Smart base64: only match strings with known magic prefixes (from jsluice)
        # eyJ = JWT/JSON, YTo = PHP serialize, Tzo = PHP serialize obj,
        # PD[89] = <?xml/<?php, rO0 = Java serialized object
        ('base64_jwt_or_serialized', '((?:eyJ|YTo|Tzo|PD[89]|rO0)[A-Za-z0-9+/_%\\-]{20,}={0,2})'),

        # Hex encoded strings (min 32 chars hex = 16 bytes, must be even length)
        ('hex_encoded', '(?:^|[\\x22\\x27\\s=:,])((?:[0-9a-fA-F]{2}){20,})(?:$|[\\x22\\x27\\s,])'),

        # Removed: url_encoded_data - too noisy, normal URLs contain %XX sequences

        # Removed: unicode_escaped - too noisy, matches all localized strings (country names etc.)
        # Removed: html_entity_encoded - same issue, matches normal HTML content

        # === LINKFINDER-STYLE URL/PATH EXTRACTION (from FransLinkfinder) ===
        # Full URLs with protocol
        ('linkfinder_full_url', '(?:[\\x22\\x27])((?:https?://|//)[^\\x22\\x27><,;|\\s]{5,})(?:[\\x22\\x27])'),
        # Relative paths starting with / ../ ./
        ('linkfinder_relative_path', '(?:[\\x22\\x27])((?:/|\\.\\./|\\./)[^\\x22\\x27><,;|\\s*()(%%$^/\\\\\\[\\]]{1,}[^\\x22\\x27><,;|\\s()]{1,})(?:[\\x22\\x27])'),
        # File references with common extensions
        ('linkfinder_file_ref', '(?:[\\x22\\x27])([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|yaml|yml|sh|bat|ps1|py|rb|pl)(?:\\?[^\\x22\\x27]{0,}|))(?:[\\x22\\x27])'),

        # === ADDITIONAL ENDPOINT PREFIXES ===
        ('login_endpoint', '[\\x22\\x27](/login[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('logout_endpoint', '[\\x22\\x27](/logout[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('token_endpoint', '[\\x22\\x27](/token[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('backup_endpoint', '[\\x22\\x27](/backup[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('private_endpoint', '[\\x22\\x27](/private[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('download_endpoint', '[\\x22\\x27](/download[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('dashboard_endpoint', '[\\x22\\x27](/dashboard[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('signup_endpoint', '[\\x22\\x27](/signup[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('register_endpoint', '[\\x22\\x27](/register[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('reset_endpoint', '[\\x22\\x27](/reset[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('forgot_endpoint', '[\\x22\\x27](/forgot[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('verify_endpoint', '[\\x22\\x27](/verify[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('callback_endpoint', '[\\x22\\x27](/callback[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('webhook_endpoint', '[\\x22\\x27](/webhook[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('websocket_endpoint', '[\\x22\\x27](/ws/[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),
        ('socket_endpoint', '[\\x22\\x27](/socket[a-zA-Z0-9/_\\-]*)[\\x22\\x27]'),

        # === NEW SaaS TOKEN PATTERNS ===
        ('vercel_token', r'vercel_[a-zA-Z0-9]{24}'),
        ('netlify_token', r'nfp_[a-zA-Z0-9]{40}'),
        ('supabase_service_key', r'sbp_[a-f0-9]{40}'),
        ('clerk_secret_key', r'sk_live_[a-zA-Z0-9]{27,}'),
        ('clerk_publishable_key', r'pk_live_[a-zA-Z0-9]{27,}'),
        ('postman_api_key', r'PMAK-[a-f0-9]{24}-[a-f0-9]{34}'),
        ('doppler_token', r'dp\.st\.[a-zA-Z0-9_\-]{40,}'),
        ('infisical_token', r'st\.[a-zA-Z0-9_\-]{30,}'),
        ('supabase_anon_key', '(?i)supabase[a-zA-Z0-9_]*(?:key|anon|url)[\\x22\\x27\\s=:]+[\\x22\\x27]?(eyJ[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+)[\\x22\\x27]?'),

        # === SSRF-INDICATIVE PARAMETERS ===
        ('ssrf_param', r'(?i)[?&](?:url|redirect|proxy|dest|destination|uri|path|target|site|feed|host|to|out|view|dir|show|navigation|open|domain|callback|return|page|load|file|document|folder|source|img|link)=(?:https?://|//|/)'),

        # === NUCLEI-TEMPLATES PATTERNS ===
        # GitHub OAuth/App tokens (we already have ghp_ but missing gho_, ghu_, ghs_)
        ('github_oauth_token', r'gho_[a-zA-Z0-9]{36}'),
        ('github_user_token', r'ghu_[a-zA-Z0-9]{36}'),
        ('github_server_token', r'ghs_[a-zA-Z0-9]{36}'),

        # SaaS API Keys/Tokens with distinctive prefixes
        ('branch_key', r'key_live_[a-zA-Z0-9]{32}'),
        ('clojars_token', r'(?i)CLOJARS_[a-z0-9]{60}'),
        ('cloudinary_url', r'cloudinary://[0-9]{15}:[0-9A-Za-z\-_]+@[0-9A-Za-z\-_]+'),
        ('crates_io_token', r'\bcio[a-zA-Z0-9]{32}\b'),
        ('databricks_token', r'(?i)\bdapi[a-h0-9]{32}\b'),
        ('duffel_token', r'duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}'),
        ('dynatrace_token', r'dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}'),
        ('frameio_token', r'fio-u-[a-zA-Z0-9\-_=]{64}'),
        ('nuget_key', r'oy2[a-z0-9]{43}'),
        ('openrouter_key', r'sk-or-v1-[a-fA-F0-9]{48,64}'),
        ('razorpay_key', r'rzp_(?:live|test)_[a-zA-Z0-9]{14}'),
        ('rubygems_token', r'rubygems_[a-f0-9]{48}'),
        ('stackhawk_key', r'hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}'),
        ('zapier_webhook', r'https://(?:www\.)?hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/'),
    ]

def _direct_regexs_chunk_3():
    return [
        ('hashicorp_tf_token', r'(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}'),

        # Contextual patterns (service name + key value)
        ('adafruit_key', '(?i)adafruit.{0,20}[=:].{0,5}([a-z0-9_\\-]{32})'),
        ('airtable_key', '(?i)airtable.{0,20}[=:].{0,5}([a-z0-9]{17})'),
        ('beamer_token', r'b_[a-z0-9=_\-]{44}'),
        ('codecov_token', '(?i)codecov.{0,20}[=:].{0,5}([a-z0-9]{32})'),
        ('coinbase_key', '(?i)coinbase.{0,20}[=:].{0,5}([a-z0-9_\\-]{64})'),
        ('contentful_token', '(?i)contentful.{0,20}[=:].{0,5}([a-z0-9=_\\-]{43})'),
        ('code_climate_token', '(?i)codeclima.{0,50}([a-f0-9]{64})'),
        ('datadog_token', '(?i)datadog.{0,20}[=:].{0,5}([a-z0-9]{40})'),
        ('fastly_token', '(?i)fastly.{0,20}[=:].{0,5}([a-z0-9=_\\-]{32})'),
        ('figma_token', r'(?i)figma.{0,20}([0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
        ('finnhub_token', '(?i)finnhub.{0,20}[=:].{0,5}([a-z0-9]{20})'),
        ('gitter_token', '(?i)gitter.{0,20}[=:].{0,5}([a-z0-9_\\-]{40})'),
        ('gocardless_token', r'live_[a-zA-Z0-9\-_=]{40}'),
        ('jenkins_crumb', r'(?i)jenkins.{0,10}(?:crumb)?.{0,10}([0-9a-f]{32,36})'),
        ('pendo_key', r'(?i)pendoApiKey.{0,10}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),
        ('zendesk_key', '(?i)zendesk.{0,20}[=:].{0,5}([a-z0-9]{40})'),

        # From js-analyse.yaml - generic token/key exposure pattern
        ('js_token_assignment', '(?i)(?:key|password|passwd|pass|pwd|private|credential|auth|cred|secret|access|token|secretaccesskey)(?:[_\\-][a-z]+)?\\s*[:=]'),
        # AJAX request detection
        ('ajax_request', r'(?i)new\s+XMLHttpRequest\(\)'),
    ]

_REGEXS = (
    _regexs_chunk_1() +
    _regexs_chunk_2() +
    _regexs_chunk_3() +
    _regexs_chunk_4() +
    _regexs_chunk_5()
)

_DIRECT_REGEXS = (
    _direct_regexs_chunk_1() +
    _direct_regexs_chunk_2() +
    _direct_regexs_chunk_3()
)

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener, ITab):
    # List of tuples: (name, regex_pattern) - fixes the duplicate key bug in dict
    regexs = _REGEXS

    # Direct-match patterns: these are matched WITHOUT the regex wrapper
    # (no delimiter requirement). Used for URLs, endpoints, tokens with
    # distinctive prefixes, connection strings, emails, and file references.
    direct_regexs = _DIRECT_REGEXS

    regex = r"[:|=|\'|\"|\s*|`|\xb4| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|\xb4| |,|?=|\]|\}|&|//|\*/]"
    issuename = "JSReconRadar: %s"
    issuelevel = "Information"
    issuedetail = r"""Potential Secret Find: <b>%%regex%%</b>
    <br><br><b>Note:</b> Please note that some of these issues could be false positives, a manual review is recommended."""

    # JS library filenames to skip scanning (Feature 6)
    _SKIP_JS_LIBS = [
        'jquery', 'google-analytics', 'gpt.js', 'modernizr', 'gtm.js', 'gtm',
        'fbevents', 'angular.min', 'react.min', 'vue.min', 'bootstrap.min',
        'lodash.min', 'moment.min', 'popper.min', 'axios.min', 'd3.min',
        'chart.min', 'socket.io', 'polyfill',
    ]

    # CDN domains to skip (Feature 2)
    _CDN_DOMAINS = set([
        "googleapis.com", "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net",
        "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
        "maxcdn.bootstrapcdn.com", "cdn.bootcss.com", "use.fontawesome.com",
        "fonts.googleapis.com", "fonts.gstatic.com", "www.google-analytics.com",
        "www.googletagmanager.com", "connect.facebook.net", "platform.twitter.com",
        "cdn.segment.com", "js.stripe.com", "cdn.amplitude.com", "static.hotjar.com",
        "snap.licdn.com", "bat.bing.com", "www.clarity.ms", "analytics.tiktok.com",
        "static.cloudflareinsights.com", "challenges.cloudflare.com",
        "www.gstatic.com", "apis.google.com", "maps.googleapis.com",
    ])

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JSReconRadar")

        # Use Burp's stdout/stderr for output
        import sys
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Thread safety
        self._lock = threading.Lock()
        self._seen = set()
        self._row_count = 0

        # Value-based deduplication: maps "type|value" -> list of URLs (Feature 3)
        self._value_sources = {}

        # Severity counts for stats bar (Feature 4)
        self._severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}

        # False positive values set (Feature 6)
        self._false_positive_values = set()

        # Runtime excluded domains (Feature 2)
        self._excluded_domains = set()

        # Custom regex patterns from Settings tab (list of tuples)
        self._custom_regexs = []

        # Build the UI
        self._buildUI()

        # Register as scanner check (Pro only - will silently fail on Community)
        try:
            self._callbacks.registerScannerCheck(self)
            self._log("[*] IScannerCheck registered (Pro)")
        except Exception:
            self._log("[*] IScannerCheck not available (Community Edition)")

        # Register as HTTP listener (works on both Pro and Community)
        self._callbacks.registerHttpListener(self)

        # Register the tab
        self._callbacks.addSuiteTab(self)

        self._log("[*] JSReconRadar loaded successfully!")
        self._log("[*] %d wrapped + %d direct = %d total patterns" % (
            len(self.regexs), len(self.direct_regexs),
            len(self.regexs) + len(self.direct_regexs)))
        self._log("[*] IHttpListener active - scanning HTTP responses")
        self._log("[*] Check the JSReconRadar tab for results")
        return

    def _log(self, msg):
        try:
            self._callbacks.printOutput(msg)
        except Exception:
            print(msg)

    # Severity classification for color coding
    _SEVERITY_CRITICAL = [
        "rsa private key", "ssh dsa private key", "ssh dc private key",
        "pgp private block", "ssh privkey", "private key",
        "redis uri", "mongodb uri", "postgresql uri", "mysql uri", "amqp uri",
        "js config connection string", "possible creds", "gcp service account",
        "aws secret access key",
    ]
    _SEVERITY_HIGH = [
        "google api", "google oauth", "amazon aws access key id",
        "stripe standard api", "stripe restricted api", "stripe secret key",
        "stripe publishable key", "github access token", "github pat new",
        "github pat fine grained", "gitlab pat", "slack token",
        "twilio api key", "twilio account sid", "mailgun api key",
        "paypal braintree access token", "square access token",
        "sendgrid api key", "shopify access token", "new relic key",
        "npm token", "openai api key", "anthropic api key",
        "huggingface token", "pypi token", "discord bot token",
        "telegram bot token", "mapbox token", "digitalocean token v1",
        "linear api key", "dropbox access token", "hashicorp vault token",
        "adyen client key", "http basic auth", "authorization bearer",
        "authorization basic", "json web token", "jwt token full",
        "firebase", "js config secret", "js config dsn", "sentry dsn url",
        "js generic key", "js generic snake key",
        "firebase config apikey", "firebase config domain",
        "firebase config project", "firebase config bucket",
        "firebase config messaging",
        "base64 jwt or serialized",
        "openai api key proj", "openai org id",
        "replicate api token", "groq api key", "langsmith api key",
        "voyage ai key", "stability ai key", "cohere api key",
        "mistral api key", "deepseek api key", "together ai key",
        "pinecone api key", "azure openai key",
        "credentials in url", "token in url", "todo secret",
        "vercel token", "netlify token", "supabase service key",
        "clerk secret key", "clerk publishable key", "postman api key",
        "doppler token", "infisical token", "supabase anon key",
        "github oauth token", "github user token", "github server token",
        "branch key", "clojars token", "cloudinary url", "crates io token",
        "databricks token", "duffel token", "dynatrace token", "frameio token",
        "nuget key", "openrouter key", "razorpay key", "rubygems token",
        "stackhawk key", "hashicorp tf token", "adafruit key", "airtable key",
        "beamer token", "codecov token", "coinbase key", "contentful token",
        "code climate token", "datadog token", "fastly token", "figma token",
        "finnhub token", "gitter token", "gocardless token", "jenkins crumb",
        "pendo key", "zendesk key",
        "launchdarkly client id", "mixpanel token", "segment write key",
        "amplitude api key",
        # Webhooks
        "slack webhook", "teams webhook", "mattermost webhook",
        "stripe webhook secret",
        # Distinctive prefix tokens
        "pplx api key", "dckr pat", "render api key", "railway token",
        "statsig secret", "age secret key", "flywire key",
        "planetscale token", "planetscale password",
        "turso auth token", "neon api key", "upstash redis token",
        # OAuth / OIDC
        "azure tenant id", "cognito pool id",
        # Monitoring / error tracking
        "datadog api key", "rollbar token", "bugsnag api key",
        "newrelic license", "elastic apm token",
        # Headless CMS
        "contentful delivery token", "storyblok token", "prismic token",
        # Payment
        "razorpay key id", "flutterwave key", "paystack key",
        "paddle api key", "lemonsqueezy api key",
        # Messaging
        "vonage api key", "messagebird key", "pusher key", "pusher secret",
        "ably api key",
        # Maps / Geo
        "here api key", "tomtom api key",
        # Feature flags
        "splitio key", "flagsmith key", "posthog api key", "posthog project key",
        # Hosting
        "vercel token", "fly io token", "convex deploy key",
        # Search / Database SaaS
        "typesense api key", "meilisearch key", "elasticsearch api key",
        # Gitleaks distinctive prefix tokens
        "onepassword secret key", "onepassword service account",
        "adobe client secret", "airtable pat", "alibaba access key",
        "anthropic admin key", "anthropic api key v3",
        "artifactory api key", "artifactory ref token", "authress service key",
        "aws bedrock key", "azure ad client secret", "beamer api token",
        "clickhouse cloud secret", "clojars token", "cloudflare origin ca",
        "databricks token", "defined networking token",
        "digitalocean oauth", "digitalocean refresh",
        "doppler token", "duffel token", "dynatrace token",
        "easypost prod key", "easypost test key", "facebook page token",
        "flutterwave pub", "flutterwave sec", "flutterwave enc",
        "flyio fm token", "frameio token",
        "github user token", "github server token",
        "github oauth token", "github refresh token",
        "gitlab cicd job token", "gitlab deploy token",
        "gitlab feature flag token", "gitlab feed token",
        "gitlab incoming mail", "gitlab k8s agent token",
        "gitlab oauth app secret", "gitlab pipeline trigger",
        "gitlab rrt", "gitlab runner token", "gitlab scim token",
        "grafana api key", "grafana cloud token", "grafana service account",
        "harness api key", "heroku api key v2", "huggingface org token",
        "infracost token", "intra42 client secret", "maxmind license",
        "notion token", "octopus api key", "openshift user token",
        "plaid access token", "planetscale oauth", "postman api token",
        "prefect api token", "pulumi api token", "readme api token",
        "rubygems token", "scalingo token", "sendinblue token",
        "sentry user token", "sentry org token",
        "settlemint app token", "settlemint pat", "settlemint service token",
        "shippo token", "shopify shared secret",
        "slack app token", "slack bot token", "slack user token",
        "slack config access", "slack config refresh", "slack legacy workspace",
        "sourcegraph token", "sumologic access id",
        "twilio sk", "typeform token",
        "yandex iam token", "yandex api key", "yandex aws token",
        "atlassian api token", "lob live key", "lob test key", "lob pub key",
        "mailchimp api key", "mailgun pub key", "mailgun signing key",
        "newrelic browser key", "newrelic user api key",
        "sonar token", "square access token v2",
        "slack legacy token", "slack legacy bot",
        "sidekiq sensitive url", "facebook access token v2",
        "stripe key extended", "freemius secret key",
        "k8s service account token",
        "aws access token a3t", "aws bedrock short lived",
        "dropbox long lived token",
        "gitlab pat routable", "gitlab runner routable",
        "gitlab session cookie",
        "twitter bearer token", "pypi upload token",
        "jwt base64 encoded", "gocardless live token", "mollie api key",
    ]
    _SEVERITY_MEDIUM = [
        "intercom app id", "meta pixel id", "hotjar id",
        "google tag manager", "google analytics",
        # OAuth domains (recon, not direct secrets)
        "okta domain", "auth0 domain",
        "contentful space id", "sanity project id",
        "logrocket app id",
        # Infrastructure endpoints
        "rds endpoint", "elasticache endpoint", "documentdb endpoint",
        "cosmos db endpoint", "mongo atlas host",
        "k8s api internal", "etcd endpoint", "spring actuator",
        "graphql introspection", "openid config url",
        "oauth redirect uri",
        "amazon aws url", "amazon aws url2", "amazon s3 bucket",
        "azure blob storage", "cloudflare r2 bucket", "hetzner object storage",
        "backblaze b2 bucket", "wasabi bucket", "supabase storage",
        "alibaba oss bucket", "tencent cos bucket", "huawei obs bucket",
        "baidu bos bucket", "kingsoft ks3 bucket", "ucloud ufile bucket",
        "qiniu kodo bucket", "jd cloud oss bucket", "volcengine tos bucket",
        "china telecom oos bucket",
        "oracle object storage", "linode object storage", "vultr object storage",
        "scaleway object storage", "clever cloud cellar", "minio bucket",
        "dreamhost dreamobjects", "idrive e2 bucket",
        "yandex object storage", "selectel storage", "mailru cloud storage",
        "nhn object storage", "kakao object storage", "naver object storage",
        "ibm cloud object storage", "arvancloud storage",
        "contabo object storage", "exoscale sos bucket", "cloudsigma storage",
        "upcloud object storage", "filebase bucket", "storj bucket",
        "ionos s3 bucket", "ovh object storage",
        "garage s3 bucket", "seaweedfs bucket", "ceph rgw bucket",
        "google cloud storage", "firebase db url", "cloudfront url",
        "digitalocean spaces", "staging domain", "dev domain",
        "internal domain", "test domain", "sandbox domain",
        "preprod domain", "localhost url", "ip url",
        "internal ip 10", "internal ip 172", "internal ip 192", "internal ip 127",
        "cors wildcard", "cors null", "cors credentials true",
        "source map url", "source map url2", "source map header",
        "stack trace node", "stack trace python", "stack trace java",
        "stack trace php", "stack trace ruby", "sql error", "debug mode",
        "windows path", "unix path disclosure", "email address",
        "sensitive file ref", "discord webhook",
        "xss innerhtml", "xss outerhtml", "xss document write",
        "xss eval", "xss settimeout str", "xss setinterval str", "xss jquery html",
        "postmessage listener", "postmessage send",
        "open redirect param", "proto pollution", "constructor proto",
        "object assign merge", "jsonp callback", "debug param",
        "ssrf param",
        "zapier webhook", "js token assignment", "ajax request",
    ]
    # Everything else is INFO (low) - endpoints, encoded data, etc.

    _COLOR_CRITICAL = Color(255, 77, 77)    # Red
    _COLOR_HIGH = Color(255, 153, 51)       # Orange
    _COLOR_MEDIUM = Color(255, 255, 102)    # Yellow
    _COLOR_INFO = Color(200, 200, 200)      # Light gray

    def _get_severity(self, secret_type):
        st = secret_type.lower()
        # Custom patterns from Settings tab are always HIGH
        if st.startswith("custom:"):
            return "HIGH"
        for s in self._SEVERITY_CRITICAL:
            if s in st:
                return "CRITICAL"
        for s in self._SEVERITY_HIGH:
            if s in st:
                return "HIGH"
        for s in self._SEVERITY_MEDIUM:
            if s in st:
                return "MEDIUM"
        return "INFO"

    def _get_severity_color(self, severity):
        if severity == "CRITICAL":
            return self._COLOR_CRITICAL
        elif severity == "HIGH":
            return self._COLOR_HIGH
        elif severity == "MEDIUM":
            return self._COLOR_MEDIUM
        return self._COLOR_INFO

    def _buildUI(self):
        self._panel = JPanel(BorderLayout())

        # Store request/response pairs keyed by row number
        self._http_messages = {}

        # Active thread counter
        self._active_threads = 0

        # === TOP BAR: title + controls ===
        topContainer = JPanel()
        topContainer.setLayout(BorderLayout())

        # Row 1: Title + buttons
        titlePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        titleLabel = JLabel("JSReconRadar")
        titleLabel.setFont(Font("Dialog", Font.BOLD, 16))
        titlePanel.add(titleLabel)

        self._countLabel = JLabel("  Results: 0")
        self._countLabel.setFont(Font("Dialog", Font.PLAIN, 12))
        titlePanel.add(self._countLabel)

        self._statusLabel = JLabel("  |  Idle")
        self._statusLabel.setFont(Font("Dialog", Font.ITALIC, 11))
        self._statusLabel.setForeground(Color(100, 100, 100))
        titlePanel.add(self._statusLabel)

        # Stats label (Feature 4)

        buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))

        self._scopeCheckbox = JCheckBox("Scope only", False)
        self._scopeCheckbox.setToolTipText("Only scan URLs in Burp Target scope")
        buttonPanel.add(self._scopeCheckbox)

        clearButton = JButton("Clear")
        clearButton.addActionListener(ClearActionListener(self))
        buttonPanel.add(clearButton)

        exportButton = JButton("Export CSV")
        exportButton.addActionListener(ExportActionListener(self))
        buttonPanel.add(exportButton)

        saveButton = JButton("Save")
        saveButton.addActionListener(SaveActionListener(self))
        buttonPanel.add(saveButton)

        loadButton = JButton("Load")
        loadButton.addActionListener(LoadActionListener(self))
        buttonPanel.add(loadButton)

        scanHistoryButton = JButton("Scan History")
        scanHistoryButton.setToolTipText("Scan all proxy history items for secrets")
        scanHistoryButton.addActionListener(ScanHistoryActionListener(self))
        buttonPanel.add(scanHistoryButton)

        settingsButton = JButton("Settings")
        settingsButton.setToolTipText("Custom regex patterns")
        settingsButton.addActionListener(SettingsButtonListener(self))
        buttonPanel.add(settingsButton)

        row1 = JPanel(BorderLayout())
        row1.add(titlePanel, BorderLayout.WEST)
        row1.add(buttonPanel, BorderLayout.EAST)

        # Row 2: Severity toggles + text search
        filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        filterPanel.add(JLabel("Severity: "))
        self._sevCritical = JToggleButton("CRITICAL", True)
        self._sevCritical.setFont(Font("Dialog", Font.BOLD, 11))
        self._sevCritical.setForeground(Color(255, 80, 80))
        self._sevCritical.setToolTipText("Show/hide CRITICAL findings")
        filterPanel.add(self._sevCritical)

        self._sevHigh = JToggleButton("HIGH", True)
        self._sevHigh.setFont(Font("Dialog", Font.BOLD, 11))
        self._sevHigh.setForeground(Color(255, 160, 50))
        self._sevHigh.setToolTipText("Show/hide HIGH findings")
        filterPanel.add(self._sevHigh)

        self._sevMedium = JToggleButton("MEDIUM", True)
        self._sevMedium.setFont(Font("Dialog", Font.BOLD, 11))
        self._sevMedium.setForeground(Color(200, 200, 0))
        self._sevMedium.setToolTipText("Show/hide MEDIUM findings")
        filterPanel.add(self._sevMedium)

        self._sevInfo = JToggleButton("INFO", True)
        self._sevInfo.setFont(Font("Dialog", Font.PLAIN, 11))
        self._sevInfo.setToolTipText("Show/hide INFO findings")
        filterPanel.add(self._sevInfo)

        # Wire up toggle listeners
        sevListener = SeverityToggleListener(self)
        self._sevCritical.addActionListener(sevListener)
        self._sevHigh.addActionListener(sevListener)
        self._sevMedium.addActionListener(sevListener)
        self._sevInfo.addActionListener(sevListener)

        filterPanel.add(JLabel("    Search: "))
        self._filterField = JTextField(30)
        self._filterField.setToolTipText("Type to filter results by URL, type, or value")
        filterPanel.add(self._filterField)
        self._filterCountLabel = JLabel("")
        self._filterCountLabel.setFont(Font("Dialog", Font.PLAIN, 11))
        filterPanel.add(self._filterCountLabel)

        topContainer.add(row1, BorderLayout.NORTH)
        topContainer.add(filterPanel, BorderLayout.SOUTH)
        topContainer.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5))

        self._panel.add(topContainer, BorderLayout.NORTH)

        # === TABLE with Severity column + Sources column ===
        columnNames = ["#", "Severity", "URL", "Secret Type", "Matched Value", "Sources", "Timestamp"]
        self._tableModel = DefaultTableModel(columnNames, 0)
        self._table = JTable(self._tableModel)

        self._sorter = TableRowSorter(self._tableModel)
        self._table.setRowSorter(self._sorter)

        # Column widths
        self._table.getColumnModel().getColumn(0).setPreferredWidth(40)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(70)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(380)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(150)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(280)
        self._table.getColumnModel().getColumn(5).setPreferredWidth(60)
        self._table.getColumnModel().getColumn(6).setPreferredWidth(130)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        # Color-coded severity renderer
        self._table.setDefaultRenderer(self._table.getColumnClass(0), SeverityRenderer())

        # Right-click context menu (Feature 1)
        self._popupMenu = JPopupMenu()

        menuCopyValue = JMenuItem("Copy Value")
        menuCopyValue.addActionListener(TablePopupActionListener(self, "copy_value"))
        self._popupMenu.add(menuCopyValue)

        menuCopyURL = JMenuItem("Copy URL")
        menuCopyURL.addActionListener(TablePopupActionListener(self, "copy_url"))
        self._popupMenu.add(menuCopyURL)

        menuSendRepeater = JMenuItem("Send to Repeater")
        menuSendRepeater.addActionListener(TablePopupActionListener(self, "send_repeater"))
        self._popupMenu.add(menuSendRepeater)

        menuSendIntruder = JMenuItem("Send to Intruder")
        menuSendIntruder.addActionListener(TablePopupActionListener(self, "send_intruder"))
        self._popupMenu.add(menuSendIntruder)

        menuExcludeDomain = JMenuItem("Exclude this domain")
        menuExcludeDomain.addActionListener(TablePopupActionListener(self, "exclude_domain"))
        self._popupMenu.add(menuExcludeDomain)

        menuMarkFP = JMenuItem("Mark as False Positive")
        menuMarkFP.addActionListener(TablePopupActionListener(self, "mark_fp"))
        self._popupMenu.add(menuMarkFP)

        self._table.addMouseListener(TableMouseAdapter(self))

        tableScrollPane = JScrollPane(self._table)

        # === VIEWER PANE ===
        self._requestViewer = self._callbacks.createMessageEditor(None, False)
        self._responseViewer = self._callbacks.createMessageEditor(None, False)
        self._matchViewer = self._callbacks.createTextEditor()
        self._matchViewer.setEditable(False)

        viewerTabs = JTabbedPane()
        viewerTabs.addTab("Request", self._requestViewer.getComponent())
        viewerTabs.addTab("Response", self._responseViewer.getComponent())
        viewerTabs.addTab("Result", self._matchViewer.getComponent())
        self._viewerTabs = viewerTabs

        # === SETTINGS DIALOG (Custom Regex) - opened via button ===
        self._customRegexArea = JTextArea(20, 60)
        self._customRegexArea.setText(
            "# Custom regex patterns - one per line as: name|regex\n"
            "# Example:\n"
            "# company_api_key|COMPANY_[a-zA-Z0-9]{32}\n"
            "# internal_token|int_tok_[a-zA-Z0-9]{16,}\n"
            "#\n"
            "# Custom patterns are classified as HIGH severity.\n"
        )
        self._customRegexArea.setFont(Font("Monospaced", Font.PLAIN, 13))

        # === SPLIT PANE ===
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setTopComponent(tableScrollPane)
        splitPane.setBottomComponent(viewerTabs)
        splitPane.setResizeWeight(0.6)
        splitPane.setDividerLocation(300)

        self._panel.add(splitPane, BorderLayout.CENTER)

        # Row selection listener
        self._table.getSelectionModel().addListSelectionListener(
            ResultSelectionListener(self)
        )

        # Filter listener
        self._filterField.getDocument().addDocumentListener(
            FilterDocumentListener(self)
        )

    def getTabCaption(self):
        return "JSReconRadar"

    def getUiComponent(self):
        return self._panel

    # Words/patterns that indicate false positives (error messages, code, etc.)
    _FP_VALUES = [
        "true", "false", "null", "undefined", "none", "function",
        "return", "length", "error", "invalid", "expired",
        "not_found", "not found", "required", "missing",
        "api_error", "api error",
        "buffer", "events", "util", "path", "stream", "process", "webpack",
    ]

    # Noise patterns for PDF artifacts, build artifacts, framework internals, etc.
    _FP_NOISE_PATTERNS = re.compile(
        r'^/[A-Z][a-z]+$'                # PDF object refs: /Type, /Parent, /Page
        r'|^\d+\s+\d+\s+R$'             # PDF references: 1 0 R
        r'|^webpack'                      # Webpack artifacts
        r'|^xl/'                          # Excel internals
        r'|^docProps/'                    # Office internals
        r'|^_rels/'                       # Office relationship files
        r'|^worksheets/'                  # Excel worksheets
        r'|^theme/'                       # Office themes
        r'|_ngcontent'                    # Angular internals
        r'|^/[a-zA-Z]$'                  # Single letter paths: /a, /b
        r'|^https?://$'                  # Empty protocols
    )

    # Build module names that are not secrets
    _FP_MODULE_NAMES = set([
        'buffer', 'events', 'util', 'path', 'stream', 'process',
    ])

    # Known noise domains to skip in URL-type values
    _NOISE_DOMAINS = set([
        'w3.org', 'www.w3.org', 'xml.org', 'xmlns.com',
        'example.com', 'example.org', 'test.com', 'localhost',
        'schema.org', 'schemas.xmlsoap.org', 'purl.org', 'www.example.com',
    ])

    # Patterns that are clearly code, not secrets
    _FP_PATTERNS = re.compile(
        r'^[A-Z_]{4,}$'           # ALL_CAPS_CONSTANTS like INVALID_TOKEN
        r'|^\(.*\)$'              # (parenthesized expressions)
        r'|^function'             # function declarations
        r'|\.\w+\('              # method calls like .some(
        r'|\.length'              # .length property
        r'|\.prototype'           # .prototype
        r'|\bif\b|\belse\b|\bfor\b|\bvar\b|\blet\b|\bconst\b'  # JS keywords
        r'|^[ue]\.'              # Jython u. or e. object access
        r'|^\w+\.\w+\.\w+\('    # chained calls like a.b.c(
    )

    # Pattern for i18n/translation key paths like "search.operator.slug-contains.name"
    # Must contain at least 2 dots (dotted path) to distinguish from tokens like sk-proj-xxx
    _FP_I18N_PATTERN = re.compile(
        r'^[a-z][a-z0-9\-]*\.[a-z][a-z0-9\-]*\.[a-z][a-z0-9\-\.]*$'
    )

    # Pattern for values that look like labels/descriptions, not secrets
    _FP_LABEL_PATTERN = re.compile(
        r'(?i)^[a-z]+(?:[\.\-][a-z]+){2,}(?:\.(?:name|label|title|description|text|message|placeholder|hint|error|help|info|warning|tooltip|caption))?$'
    )

    # Prefixes that indicate non-secret encoded data (SRI hashes, nonces, etc.)
    _FP_PREFIXES = [
        "sha256-", "sha384-", "sha512-",  # Subresource Integrity hashes
        "data:image/", "data:font/", "data:application/",  # data URIs
        "nonce-",  # CSP nonces
    ]

    def _is_false_positive(self, value):
        """Check if a matched value is likely a false positive."""
        # Check if explicitly marked as FP (Feature 6)
        if value in self._false_positive_values:
            return True

        # For "key = value" format, check the value part
        check_val = value
        if " = " in value:
            check_val = value.split(" = ", 1)[1]

        v = check_val.lower().strip()

        # Too short or too long
        if len(v) < 4 or len(v) > 2000:
            return True
        # Known false positive values
        for fp in self._FP_VALUES:
            if v == fp:
                return True
        # Known false positive prefixes
        for prefix in self._FP_PREFIXES:
            if v.startswith(prefix):
                return True
        # Looks like code, not a secret
        if self._FP_PATTERNS.search(check_val):
            return True
        # i18n translation key paths (e.g., "search.operator.slug-contains.name")
        # Only block if the value is all-lowercase dotted path (secrets have mixed case/digits)
        if self._FP_I18N_PATTERN.match(v):
            # But allow if it contains a long digit sequence (could be a real key)
            if not re.search(r'\d{4,}', check_val):
                return True
        # Label/description paths (all lowercase, no long digit runs)
        if self._FP_LABEL_PATTERN.match(v):
            if not re.search(r'\d{4,}', check_val):
                return True
        # Value ends with common non-secret suffixes AND is all lowercase dotted path
        if v.endswith(('.name', '.label', '.title', '.description', '.text',
                       '.message', '.placeholder', '.hint', '.error', '.help')):
            if '.' in v and not re.search(r'[A-Z]', check_val) and not re.search(r'\d{4,}', check_val):
                return True
        # Starts with u' (Jython unicode string repr)
        if value.startswith("(u'") or value.startswith('(u"'):
            return True

        # Noise patterns: PDF artifacts, webpack, excel internals, angular, etc.
        if self._FP_NOISE_PATTERNS.search(check_val):
            return True

        # Exact match for build module names
        if v in self._FP_MODULE_NAMES:
            return True

        # Noise domains: skip URL values pointing to known spec/example domains
        if v.startswith('http://') or v.startswith('https://') or v.startswith('//'):
            try:
                # Extract domain from URL
                url_body = v
                if url_body.startswith('//'):
                    url_body = url_body[2:]
                elif '://' in url_body:
                    url_body = url_body.split('://', 1)[1]
                domain = url_body.split('/')[0].split(':')[0].lower()
                if domain in self._NOISE_DOMAINS:
                    return True
                # Also check if domain ends with a noise domain
                for nd in self._NOISE_DOMAINS:
                    if domain == nd or domain.endswith('.' + nd):
                        return True
            except Exception:
                pass

        # Placeholder values commonly found in code (not real secrets)
        _placeholder_indicators = [
            'example', 'placeholder', 'your_', 'YOUR_', 'xxx', 'XXXX',
            'change_me', 'CHANGE_ME', 'replace_', 'INSERT_', 'TODO',
            '<your', 'sample', 'dummy', 'test_key', 'fake_',
        ]
        for indicator in _placeholder_indicators:
            if indicator in check_val:
                return True

        # Values that are just repeated characters (e.g., "aaaaaaa", "ababab")
        if len(v) >= 4:
            # All same character
            if len(set(v)) == 1:
                return True
            # Alternating pattern (e.g., "ababab")
            if len(v) >= 6 and len(set(v)) == 2:
                pattern = v[:2]
                if pattern * (len(v) // 2) == v[:len(pattern) * (len(v) // 2)]:
                    return True

        return False

    def applyFilters(self):
        """Combine severity toggle filters with text search filter."""
        try:
            filters = ArrayList()

            # Severity filter: build OR filter for selected severities
            sev_filters = ArrayList()
            if self._sevCritical.isSelected():
                sev_filters.add(RowFilter.regexFilter("^CRITICAL$", 1))
            if self._sevHigh.isSelected():
                sev_filters.add(RowFilter.regexFilter("^HIGH$", 1))
            if self._sevMedium.isSelected():
                sev_filters.add(RowFilter.regexFilter("^MEDIUM$", 1))
            if self._sevInfo.isSelected():
                sev_filters.add(RowFilter.regexFilter("^INFO$", 1))

            if sev_filters.size() > 0:
                filters.add(RowFilter.orFilter(sev_filters))
            else:
                # Nothing selected = show nothing
                self._sorter.setRowFilter(RowFilter.regexFilter("^$", 1))
                self._filterCountLabel.setText("  Showing 0 / %d" % self._tableModel.getRowCount())
                return

            # Text search filter (across all columns)
            text = self._filterField.getText()
            if text and len(text) > 0:
                try:
                    filters.add(RowFilter.regexFilter("(?i)" + text))
                except Exception:
                    pass

            # Combine all filters with AND
            if filters.size() > 0:
                self._sorter.setRowFilter(RowFilter.andFilter(filters))
            else:
                self._sorter.setRowFilter(None)

            visible = self._table.getRowCount()
            total = self._tableModel.getRowCount()
            if visible < total:
                self._filterCountLabel.setText("  Showing %d / %d" % (visible, total))
            else:
                self._filterCountLabel.setText("")
        except Exception:
            self._sorter.setRowFilter(None)
            self._filterCountLabel.setText("")


    def _fillEditorSearchBox(self, editor, search_term):
        """Find the search JTextField in a MessageEditor and set its text."""
        try:
            self._findAndFillTextField(editor.getComponent(), search_term)
        except Exception:
            pass

    def _findAndFillTextField(self, component, text):
        from javax.swing import JTextField as JTF
        if isinstance(component, JTF):
            component.setText(text)
            return True
        try:
            for i in range(component.getComponentCount()):
                if self._findAndFillTextField(component.getComponent(i), text):
                    return True
        except Exception:
            pass
        return False

    def _updateStatus(self, msg):
        try:
            self._statusLabel.setText("  |  " + msg)
        except Exception:
            pass

    def _updateStatsLabel(self):
        """Update severity counts on the toggle buttons."""
        try:
            c = self._severity_counts
            self._sevCritical.setText("CRITICAL (%d)" % c.get("CRITICAL", 0))
            self._sevHigh.setText("HIGH (%d)" % c.get("HIGH", 0))
            self._sevMedium.setText("MEDIUM (%d)" % c.get("MEDIUM", 0))
            self._sevInfo.setText("INFO (%d)" % c.get("INFO", 0))
        except Exception:
            pass

    def _addResult(self, url, secret_type, matched_value, messageInfo=None):
        try:
            matched_value = str(matched_value).strip()
            if not matched_value or len(matched_value) < 3:
                return
            if self._is_false_positive(matched_value):
                return
            url_str = str(url)

            # Value-based dedup key: type|value only (Feature 3)
            value_dedup_key = secret_type + "|" + matched_value
            # URL-specific dedup to avoid reprocessing same URL+type+value
            full_dedup_key = url_str + "|" + value_dedup_key

            self._lock.acquire()
            try:
                if full_dedup_key in self._seen:
                    return
                self._seen.add(full_dedup_key)

                # Check if this type+value already exists from a different URL
                if value_dedup_key in self._value_sources:
                    # Update existing row: add URL to sources, update count
                    source_list = self._value_sources[value_dedup_key]
                    if url_str not in source_list:
                        source_list.append(url_str)
                    existing_row_num = self._value_sources[value_dedup_key + "_row"]
                    # Store messageInfo for the new URL too
                    if messageInfo is not None:
                        self._http_messages[str(existing_row_num)] = messageInfo
                    # Find and update the Sources column in the table
                    source_count = len(source_list)
                    for r in range(self._tableModel.getRowCount()):
                        if str(self._tableModel.getValueAt(r, 0)) == str(existing_row_num):
                            self._tableModel.setValueAt(str(source_count), r, 5)
                            break
                    return
                else:
                    self._row_count = self._row_count + 1
                    row_num = self._row_count
                    self._value_sources[value_dedup_key] = [url_str]
                    self._value_sources[value_dedup_key + "_row"] = row_num
            finally:
                self._lock.release()

            severity = self._get_severity(secret_type)

            # Update severity counts (Feature 4)
            self._lock.acquire()
            try:
                self._severity_counts[severity] = self._severity_counts.get(severity, 0) + 1
            finally:
                self._lock.release()

            now = datetime.datetime.now()
            timestamp = "%d-%02d-%02d %02d:%02d:%02d" % (
                now.year, now.month, now.day, now.hour, now.minute, now.second)
            row_data = [str(row_num), severity, url_str, secret_type, matched_value, "1", timestamp]

            if messageInfo is not None:
                self._http_messages[str(row_num)] = messageInfo

            self._tableModel.addRow(row_data)
            self._countLabel.setText("  Results: %d" % row_num)
            self._updateStatsLabel()

            self._log("[+] [%s] %s -> %s : %s" % (severity, url_str, secret_type, matched_value[:80]))
        except Exception:
            self._log("[!] _addResult error: %s" % traceback.format_exc())

    # File extensions to skip (binary/non-text content)
    _SKIP_EXTENSIONS = (
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.bmp', '.webp',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.avi', '.mov', '.webm', '.ogg',
        '.zip', '.gz', '.tar', '.rar', '.7z',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.css', '.map',
    )

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        try:
            response = messageInfo.getResponse()
            if response is None:
                return

            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            url_str = str(url)

            # If "Scope only" is checked, skip out-of-scope URLs
            try:
                if self._scopeCheckbox.isSelected():
                    if not self._callbacks.isInScope(url):
                        return
            except Exception:
                pass

            # CDN domain check (Feature 2)
            try:
                hostname = url.getHost().lower()
                skip = False
                for cdn in self._CDN_DOMAINS:
                    if hostname == cdn or hostname.endswith("." + cdn):
                        skip = True
                        break
                if not skip:
                    for excl in self._excluded_domains:
                        if hostname == excl or hostname.endswith("." + excl):
                            skip = True
                            break
                if skip:
                    return
            except Exception:
                pass

            # Run scanning in a background thread so we don't block HTTP traffic
            t = threading.Thread(target=self._scanResponse, args=(messageInfo, url, url_str))
            t.daemon = True
            t.start()

        except Exception:
            self._log("[!] processHttpMessage error:\n%s" % traceback.format_exc())

    # Maximum response size to scan (5MB)
    _MAX_RESPONSE_SIZE = 5 * 1024 * 1024

    def _addToSiteMap(self, url_string):
        """Best-effort: add a discovered URL to Burp's site map (no HTTP request sent)."""
        try:
            if not url_string.startswith('http'):
                return
            from java.net import URL as JavaURL
            parsed = JavaURL(url_string)
            host = parsed.getHost()
            port = parsed.getPort()
            protocol = parsed.getProtocol()
            is_https = (protocol == 'https')
            if port == -1:
                port = 443 if is_https else 80
            # Build a simple GET request for the URL
            req = self._helpers.buildHttpRequest(parsed)
            # Build HttpService and add to site map with request only
            http_service = self._helpers.buildHttpService(host, port, is_https)
            self._callbacks.addToSiteMap(SiteMapEntry(req, None, http_service))
        except Exception:
            pass

    def _scanResponse(self, messageInfo, url, url_str):
        self._lock.acquire()
        try:
            self._active_threads = self._active_threads + 1
            thread_count = self._active_threads
        finally:
            self._lock.release()
        self._updateStatus("Scanning... (%d active)" % thread_count)

        try:
            response = messageInfo.getResponse()
            if response is None:
                return

            # Skip responses over 5MB
            if len(response) > self._MAX_RESPONSE_SIZE:
                self._log("[*] Skipped %s (%.1f MB > 5MB limit)" % (url_str, len(response) / 1048576.0))
                return

            # Skip binary file types
            url_lower = url_str.lower().split('?')[0]
            for ext in self._SKIP_EXTENSIONS:
                if url_lower.endswith(ext):
                    return

            # Check response headers: skip binary content types and error status codes
            try:
                resp_info = self._helpers.analyzeResponse(response)
                # Skip 4xx/5xx error responses (contain generic error pages, not target code)
                status_code = resp_info.getStatusCode()
                if status_code >= 400:
                    return
                headers = resp_info.getHeaders()
                for header in headers:
                    h = str(header).lower()
                    if h.startswith("content-type:"):
                        if "image/" in h or "font/" in h or "audio/" in h or "video/" in h or "octet-stream" in h:
                            return
                        break
            except Exception:
                pass

            # Skip known JS libraries (Feature 6)
            url_path_lower = url_lower.split('?')[0] if '?' in url_lower else url_lower
            for lib_name in self._SKIP_JS_LIBS:
                if lib_name in url_path_lower:
                    return

            # Get response body only (skip headers)
            try:
                resp_info = self._helpers.analyzeResponse(response)
                body_offset = resp_info.getBodyOffset()
                response_bytes = response[body_offset:]
                response_body = self._helpers.bytesToString(response_bytes)
            except Exception:
                try:
                    response_body = self._helpers.bytesToString(response)
                except Exception:
                    return

            if response_body is None:
                return
            resp_len = len(response_body)
            if resp_len < 10:
                return

            self._log("[*] Scanning: %s (%d bytes)" % (url_str, resp_len))
            found_count = 0

            # Also scan an unescaped version of the response
            # This catches secrets inside JSON-in-JS strings where quotes are \"
            unescaped_body = response_body.replace('\\"', '"').replace("\\'", "'")

            # ===== DIRECT-MATCH PATTERNS (run on both original and unescaped) =====
            for scan_body in [response_body, unescaped_body]:
                for reg in self.direct_regexs:
                    reg_name = reg[0]
                    reg_pattern = reg[1]
                    try:
                        myre = re.compile(reg_pattern)
                        match_vals = myre.findall(scan_body)
                        for ref in match_vals:
                            if isinstance(ref, tuple):
                                parts = [str(x).strip() for x in ref if x and str(x).strip()]
                                if len(parts) == 2:
                                    ref = parts[0] + " = " + parts[1]
                                elif len(parts) == 1:
                                    ref = parts[0]
                                elif len(parts) > 2:
                                    ref = " | ".join(parts)
                                else:
                                    continue
                            ref = str(ref).strip()
                            if not ref:
                                continue
                            # Skip IP matches inside SVG path data / coordinate strings
                            if reg_name in ('external_ip', 'internal_ip_10', 'internal_ip_172', 'internal_ip_192', 'internal_ip_127'):
                                ip_pos = scan_body.find(ref)
                                if ip_pos > 0:
                                    ctx_start = max(0, ip_pos - 40)
                                    ctx_end = min(len(scan_body), ip_pos + len(ref) + 40)
                                    ctx = scan_body[ctx_start:ctx_end]
                                    # SVG path data: dense mix of decimals, commas, letters like M/L/C/Z/A/S/Q/H/V
                                    if re.search(r'[MLCZSQAHVT]\s*[\d\.\-,]+' + re.escape(ref), ctx) or re.search(r'\d[\d\.\-,]{10,}' + re.escape(ref), ctx):
                                        continue
                                    # viewBox or similar SVG attributes
                                    if re.search(r'(?i)(?:viewBox|points|d)=', ctx):
                                        continue
                            # Skip email matches that are part of URLs (e.g. https://key@host, ftp://user@host)
                            if reg_name == 'email_address':
                                at_idx = ref.find('@')
                                local_part = ref[:at_idx] if at_idx > 0 else ref
                                email_pos = scan_body.find(local_part + '@')
                                if email_pos > 0:
                                    before = scan_body[max(0, email_pos - 50):email_pos]
                                    if '://' in before and '@' not in before:
                                        continue
                            # Reclassify linkfinder URLs that match known service patterns
                            match_name = reg_name
                            if match_name == 'linkfinder_full_url':
                                ref_lower = ref.lower()
                                if '.s3.amazonaws.com' in ref_lower or 's3.amazonaws.com/' in ref_lower or '.s3-' in ref_lower:
                                    match_name = 'amazon_s3_bucket'
                                elif '.blob.core.windows.net' in ref_lower:
                                    match_name = 'azure_blob_storage'
                                elif 'storage.googleapis.com' in ref_lower or 'storage.cloud.google.com' in ref_lower:
                                    match_name = 'google_cloud_storage'
                                elif '.cloudfront.net' in ref_lower:
                                    match_name = 'cloudfront_url'
                                elif '.digitaloceanspaces.com' in ref_lower:
                                    match_name = 'digitalocean_spaces'
                                elif '.firebaseio.com' in ref_lower or '.firebasestorage.googleapis.com' in ref_lower:
                                    match_name = 'firebase_db_url'
                                elif '.r2.cloudflarestorage.com' in ref_lower or '.r2.dev' in ref_lower:
                                    match_name = 'cloudflare_r2_bucket'
                                elif '.fsn1.your-objectstorage.com' in ref_lower or '.nbg1.your-objectstorage.com' in ref_lower or '.hel1.your-objectstorage.com' in ref_lower or '.your-objectstorage.com' in ref_lower:
                                    match_name = 'hetzner_object_storage'
                                elif '.backblazeb2.com' in ref_lower or '.b2.backblaze' in ref_lower:
                                    match_name = 'backblaze_b2_bucket'
                                elif '.wasabisys.com' in ref_lower:
                                    match_name = 'wasabi_bucket'
                                elif '.supabase.co/storage' in ref_lower or '.supabase.in/storage' in ref_lower:
                                    match_name = 'supabase_storage'
                                # Chinese cloud providers
                                elif '.aliyuncs.com' in ref_lower:
                                    match_name = 'alibaba_oss_bucket'
                                elif '.myqcloud.com' in ref_lower:
                                    match_name = 'tencent_cos_bucket'
                                elif '.myhuaweicloud.com' in ref_lower or '.huaweicloud.com' in ref_lower:
                                    match_name = 'huawei_obs_bucket'
                                elif '.bcebos.com' in ref_lower:
                                    match_name = 'baidu_bos_bucket'
                                elif '.ksyuncs.com' in ref_lower or '.ks3-' in ref_lower:
                                    match_name = 'kingsoft_ks3_bucket'
                                elif '.ucloud.cn' in ref_lower or '.ufileos.com' in ref_lower:
                                    match_name = 'ucloud_ufile_bucket'
                                elif '.qiniucs.com' in ref_lower or '.qiniudn.com' in ref_lower or '.qbox.me' in ref_lower:
                                    match_name = 'qiniu_kodo_bucket'
                                elif '.jdcloud-oss.com' in ref_lower:
                                    match_name = 'jd_cloud_oss_bucket'
                                elif '.volces.com' in ref_lower or '.volcengine' in ref_lower:
                                    match_name = 'volcengine_tos_bucket'
                                elif '.ctyunapi.cn' in ref_lower or '.ctyun.cn' in ref_lower:
                                    match_name = 'china_telecom_oos_bucket'
                                # S3-compatible / indie providers
                                elif '.compat.objectstorage.' in ref_lower and '.oraclecloud.com' in ref_lower:
                                    match_name = 'oracle_object_storage'
                                elif '.linodeobjects.com' in ref_lower:
                                    match_name = 'linode_object_storage'
                                elif '.vultrobjects.com' in ref_lower:
                                    match_name = 'vultr_object_storage'
                                elif '.scw.cloud' in ref_lower:
                                    match_name = 'scaleway_object_storage'
                                elif '.cellarfs.io' in ref_lower or '.cleverapps.io' in ref_lower:
                                    match_name = 'clever_cloud_cellar'
                                elif '.dream.io' in ref_lower or '.objects-us-east-1.dream.io' in ref_lower:
                                    match_name = 'dreamhost_dreamobjects'
                                elif '.idrivee2-' in ref_lower or '.idrivee2.com' in ref_lower:
                                    match_name = 'idrive_e2_bucket'
                                elif '.storage.yandexcloud.net' in ref_lower:
                                    match_name = 'yandex_object_storage'
                                elif '.selcdn.ru' in ref_lower or '.selectel.ru' in ref_lower:
                                    match_name = 'selectel_storage'
                                elif '.mail.ru' in ref_lower and 'storage' in ref_lower:
                                    match_name = 'mailru_cloud_storage'
                                elif '.obistore.com' in ref_lower or '.nhncloudservice.com' in ref_lower:
                                    match_name = 'nhn_object_storage'
                                elif '.kakaocloud.com' in ref_lower:
                                    match_name = 'kakao_object_storage'
                                elif '.ncloud.com' in ref_lower and 'objectstorage' in ref_lower:
                                    match_name = 'naver_object_storage'
                                elif '.object.storage.softlayer.net' in ref_lower or '.cloud-object-storage.appdomain.cloud' in ref_lower or '.objectstorage.service.networklayer.com' in ref_lower:
                                    match_name = 'ibm_cloud_object_storage'
                                elif '.storage.iran.liara.space' in ref_lower or '.arvancloud.ir' in ref_lower or '.arvanstorage.ir' in ref_lower:
                                    match_name = 'arvancloud_storage'
                                elif '.contaboserver.net' in ref_lower and 'storage' in ref_lower:
                                    match_name = 'contabo_object_storage'
                                elif '.exo.io' in ref_lower or '.exoscale' in ref_lower:
                                    match_name = 'exoscale_sos_bucket'
                                elif '.cloudsigma.com' in ref_lower:
                                    match_name = 'cloudsigma_storage'
                                elif '.upcloud.com' in ref_lower and 'objecto' in ref_lower:
                                    match_name = 'upcloud_object_storage'
                                elif '.filebase.com' in ref_lower or 'ipfs.filebase' in ref_lower:
                                    match_name = 'filebase_bucket'
                                elif '.storj.io' in ref_lower or 'gateway.storjshare.io' in ref_lower:
                                    match_name = 'storj_bucket'
                                elif '.ionoscloud.com' in ref_lower and 's3' in ref_lower:
                                    match_name = 'ionos_s3_bucket'
                                elif '.ovh.net' in ref_lower and ('storage' in ref_lower or 's3' in ref_lower or '.cloud.ovh.net' in ref_lower):
                                    match_name = 'ovh_object_storage'
                                elif 'minio' in ref_lower and (':9000' in ref_lower or ':9090' in ref_lower):
                                    match_name = 'minio_bucket'
                                elif '.garage.tld' in ref_lower or '.garage-s3' in ref_lower:
                                    match_name = 'garage_s3_bucket'
                                elif '.seaweedfs' in ref_lower:
                                    match_name = 'seaweedfs_bucket'
                                elif '.ceph.com' in ref_lower or 'rgw.' in ref_lower:
                                    match_name = 'ceph_rgw_bucket'
                            display_name = ' '.join([x.title() for x in match_name.split('_')])
                            self._addResult(url, display_name, ref, messageInfo)
                            found_count = found_count + 1
                            # Add discovered full URLs to Burp's site map (Feature 5)
                            if match_name == 'linkfinder_full_url' or match_name.endswith(('_bucket', '_storage', '_url', '_spaces', '_cellar')) or match_name in ('firebase_db_url', 'cloudfront_url'):
                                self._addToSiteMap(ref)
                    except Exception:
                        continue

            # ===== CUSTOM USER PATTERNS (from Settings tab) =====
            self._lock.acquire()
            try:
                custom_regexs_snapshot = list(self._custom_regexs)
            finally:
                self._lock.release()
            for scan_body in [response_body, unescaped_body]:
                for reg in custom_regexs_snapshot:
                    reg_name = reg[0]
                    reg_pattern = reg[1]
                    try:
                        myre = re.compile(reg_pattern)
                        match_vals = myre.findall(scan_body)
                        for ref in match_vals:
                            if isinstance(ref, tuple):
                                parts = [str(x).strip() for x in ref if x and str(x).strip()]
                                if len(parts) == 1:
                                    ref = parts[0]
                                elif len(parts) >= 2:
                                    ref = " | ".join(parts)
                                else:
                                    continue
                            ref = str(ref).strip()
                            if not ref:
                                continue
                            display_name = "Custom: " + ' '.join([x.title() for x in reg_name.split('_')])
                            self._addResult(url, display_name, ref, messageInfo)
                            found_count = found_count + 1
                    except Exception:
                        continue

            # ===== WRAPPED PATTERNS =====
            for reg in self.regexs:
                reg_name = reg[0]
                reg_pattern = reg[1]
                full_regex = self.regex.replace(r'%%regex%%', reg_pattern)
                try:
                    myre = re.compile(full_regex, re.VERBOSE)
                    match_vals = myre.findall(response_body)
                    for ref in match_vals:
                        display_name = ' '.join([x.title() for x in reg_name.split('_')])
                        self._addResult(url, display_name, str(ref), messageInfo)
                        found_count = found_count + 1
                except Exception:
                    continue

            if found_count > 0:
                self._log("[+] Found %d matches in %s" % (found_count, url_str))

        except Exception:
            self._log("[!] Scan error for %s:\n%s" % (url_str, traceback.format_exc()))
        finally:
            self._lock.acquire()
            try:
                self._active_threads = self._active_threads - 1
                thread_count = self._active_threads
            finally:
                self._lock.release()
            if thread_count > 0:
                self._updateStatus("Scanning... (%d active)" % thread_count)
            else:
                self._updateStatus("Idle")

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    def _scanWithRegexLists(self, baseRequestResponse):
        """Shared scanning logic for both active and passive scans."""
        scan_issues = []
        customScans = CustomScans(baseRequestResponse, self._callbacks)

        # Wrapped patterns (original regexs list)
        for reg in self.regexs:
            tmp_issues = customScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%', reg[1]),
                BurpExtender.issuename % (' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
            )
            scan_issues = scan_issues + tmp_issues
            for issue in tmp_issues:
                detail = issue.getIssueDetail()
                try:
                    match_val = re.search(r'<b>(.*?)</b>', detail).group(1)
                except Exception:
                    match_val = detail
                display_name = ' '.join([x.title() for x in reg[0].split('_')])
                self._addResult(issue.getUrl(), display_name, match_val)

        # Direct-match patterns (no wrapper)
        for reg in self.direct_regexs:
            tmp_issues = customScans.findDirectRegEx(
                reg[1],
                BurpExtender.issuename % (' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
            )
            scan_issues = scan_issues + tmp_issues
            for issue in tmp_issues:
                detail = issue.getIssueDetail()
                try:
                    match_val = re.search(r'<b>(.*?)</b>', detail).group(1)
                except Exception:
                    match_val = detail
                display_name = ' '.join([x.title() for x in reg[0].split('_')])
                self._addResult(issue.getUrl(), display_name, match_val)

        return scan_issues

    def doActiveScan(self, baseRequestResponse, pa):
        scan_issues = self._scanWithRegexLists(baseRequestResponse)
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = self._scanWithRegexLists(baseRequestResponse)
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None


class ResultSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender

    def _beautify_js(self, snippet):
        """Simple JS beautification for context snippets (Feature 7)."""
        result = snippet
        result = result.replace(";", ";\n")
        result = result.replace("{", "{\n  ")
        result = result.replace("}", "\n}\n")
        # Replace comma followed by key-like pattern
        import re as _re
        result = _re.sub(r',\s*(["\x27a-zA-Z_])', ",\n  \\1", result)
        return result

    def _buildMatchView(self, ext, msg, model_row):
        """Build a clean, formatted match context view."""
        severity = str(ext._tableModel.getValueAt(model_row, 1))
        url_str = str(ext._tableModel.getValueAt(model_row, 2))
        secret_type = str(ext._tableModel.getValueAt(model_row, 3))
        matched_value = str(ext._tableModel.getValueAt(model_row, 4))
        sources = str(ext._tableModel.getValueAt(model_row, 5))
        timestamp = str(ext._tableModel.getValueAt(model_row, 6))

        # Get the search term (value part only for key=value patterns)
        search_term = matched_value
        if " = " in search_term:
            search_term = search_term.split(" = ", 1)[1]
        if len(search_term) > 200:
            search_term = search_term[:200]

        # Get response body as string
        try:
            response = msg.getResponse()
            resp_info = ext._helpers.analyzeResponse(response)
            body_offset = resp_info.getBodyOffset()
            body_bytes = response[body_offset:]
            body = ext._helpers.bytesToString(body_bytes)
        except Exception:
            body = ext._helpers.bytesToString(msg.getResponse())

        # Find all occurrences and extract context
        contexts = []
        search_lower = search_term.lower()
        body_lower = body.lower()
        start_pos = 0
        occurrence = 0
        while True:
            idx = body_lower.find(search_lower, start_pos)
            if idx == -1:
                break
            occurrence = occurrence + 1
            # Extract context: 150 chars before and after
            ctx_start = max(0, idx - 150)
            ctx_end = min(len(body), idx + len(search_term) + 150)
            snippet = body[ctx_start:ctx_end]

            # Add line breaks around the match for readability
            prefix = "..." if ctx_start > 0 else ""
            suffix = "..." if ctx_end < len(body) else ""
            beautified = self._beautify_js(snippet)
            contexts.append((occurrence, prefix + beautified + suffix))

            start_pos = idx + len(search_term)
            if occurrence >= 5:  # Max 5 occurrences
                break

        # Build the formatted output
        lines = []
        lines.append("=" * 80)
        lines.append("  JSReconRadar - Match Details")
        lines.append("=" * 80)
        lines.append("")
        lines.append("  Severity:     %s" % severity)
        lines.append("  Type:         %s" % secret_type)
        lines.append("  URL:          %s" % url_str)
        lines.append("  Sources:      %s" % sources)
        lines.append("  Timestamp:    %s" % timestamp)
        lines.append("")
        lines.append("-" * 80)
        lines.append("  Matched Value:")
        lines.append("-" * 80)
        lines.append("")
        lines.append("  %s" % matched_value)
        lines.append("")

        if contexts:
            lines.append("-" * 80)
            total_text = " (%d shown)" % len(contexts) if occurrence >= 5 else ""
            lines.append("  Context in Response: %d occurrence(s)%s" % (len(contexts), total_text))
            lines.append("-" * 80)
            for num, snippet in contexts:
                lines.append("")
                lines.append("  [Occurrence %d]" % num)
                lines.append("")
                # Break the snippet into readable lines (~100 chars each)
                snippet_clean = snippet.replace("\r\n", "\n").replace("\r", "\n")
                for chunk_start in range(0, len(snippet_clean), 100):
                    chunk = snippet_clean[chunk_start:chunk_start + 100]
                    # Don't break in middle of words if possible
                    if chunk_start + 100 < len(snippet_clean):
                        last_space = chunk.rfind(" ")
                        last_comma = chunk.rfind(",")
                        last_semi = chunk.rfind(";")
                        break_at = max(last_space, last_comma, last_semi)
                        if break_at > 60:
                            chunk = snippet_clean[chunk_start:chunk_start + break_at + 1]
                    lines.append("    %s" % chunk)
                lines.append("")
        else:
            lines.append("")
            lines.append("  (Match not found in response body - may be in headers)")
            lines.append("")

        lines.append("=" * 80)
        output = "\n".join(lines)
        return output, search_term

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        try:
            ext = self._extender
            row = ext._table.getSelectedRow()
            if row < 0:
                return
            model_row = ext._table.convertRowIndexToModel(row)
            row_num = str(ext._tableModel.getValueAt(model_row, 0))

            msg = ext._http_messages.get(row_num)
            if msg is not None:
                # Build match view first to get search_term
                match_text, search_term = self._buildMatchView(ext, msg, model_row)

                # Set all viewers
                ext._requestViewer.setMessage(msg.getRequest(), True)
                ext._responseViewer.setMessage(msg.getResponse(), False)
                ext._matchViewer.setText(match_text)
                ext._matchViewer.setSearchExpression(search_term)

                # Auto-switch to Response tab
                ext._viewerTabs.setSelectedIndex(1)

                # Fill the search box in the Pretty viewer - user presses Enter to search
                ext._fillEditorSearchBox(ext._responseViewer, search_term)
            else:
                ext._requestViewer.setMessage(None, True)
                ext._responseViewer.setMessage(None, False)
                ext._matchViewer.setText(None)
        except Exception:
            pass


class ScanHistoryActionListener(ActionListener):
    """Scans all proxy history items for secrets in a background thread."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        t = threading.Thread(target=self._scanHistory)
        t.daemon = True
        t.start()

    def _scanHistory(self):
        ext = self._extender
        try:
            history = ext._callbacks.getProxyHistory()
            total = len(history)
            ext._log("[*] Scanning proxy history: %d items" % total)
            ext._updateStatus("Scanning history... 0/%d" % total)

            for i in range(total):
                item = history[i]
                try:
                    response = item.getResponse()
                    if response is None:
                        continue

                    # Skip responses over size limit
                    if len(response) > ext._MAX_RESPONSE_SIZE:
                        continue

                    request_info = ext._helpers.analyzeRequest(item)
                    url = request_info.getUrl()
                    url_str = str(url)

                    # Skip binary extensions
                    url_lower = url_str.lower().split('?')[0]
                    skip_ext = False
                    for file_ext in ext._SKIP_EXTENSIONS:
                        if url_lower.endswith(file_ext):
                            skip_ext = True
                            break
                    if skip_ext:
                        continue

                    # CDN domain check
                    try:
                        hostname = url.getHost().lower()
                        skip = False
                        for cdn in ext._CDN_DOMAINS:
                            if hostname == cdn or hostname.endswith("." + cdn):
                                skip = True
                                break
                        if not skip:
                            for excl in ext._excluded_domains:
                                if hostname == excl or hostname.endswith("." + excl):
                                    skip = True
                                    break
                        if skip:
                            continue
                    except Exception:
                        pass

                    # Check response headers for binary content and error codes
                    try:
                        resp_info = ext._helpers.analyzeResponse(response)
                        status_code = resp_info.getStatusCode()
                        if status_code >= 400:
                            continue
                        headers = resp_info.getHeaders()
                        skip_ct = False
                        for header in headers:
                            h = str(header).lower()
                            if h.startswith("content-type:"):
                                if "image/" in h or "font/" in h or "audio/" in h or "video/" in h or "octet-stream" in h:
                                    skip_ct = True
                                break
                        if skip_ct:
                            continue
                    except Exception:
                        pass

                    ext._scanResponse(item, url, url_str)
                except Exception:
                    continue

                if (i + 1) % 50 == 0 or (i + 1) == total:
                    ext._updateStatus("Scanning history... %d/%d" % (i + 1, total))

            ext._updateStatus("History scan complete (%d items)" % total)
            ext._log("[*] Proxy history scan complete: %d items processed" % total)
        except Exception:
            ext._log("[!] Scan history error: %s" % traceback.format_exc())
            ext._updateStatus("History scan error")


class SettingsButtonListener(ActionListener):
    """Opens a Settings dialog with custom regex patterns."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        dialog = JDialog()
        dialog.setTitle("JSReconRadar - Settings")
        dialog.setSize(700, 500)
        dialog.setLocationRelativeTo(ext._panel)
        dialog.setLayout(BorderLayout())

        dialog.add(JScrollPane(ext._customRegexArea), BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        applyBtn = JButton("Apply")
        applyBtn.addActionListener(ApplyCustomRegexActionListener(ext))
        btnPanel.add(applyBtn)
        closeBtn = JButton("Close")
        closeBtn.addActionListener(DialogCloseListener(dialog))
        btnPanel.add(closeBtn)
        dialog.add(btnPanel, BorderLayout.SOUTH)

        dialog.setVisible(True)


class DialogCloseListener(ActionListener):
    def __init__(self, dialog):
        self._dialog = dialog

    def actionPerformed(self, event):
        self._dialog.dispose()


class ApplyCustomRegexActionListener(ActionListener):
    """Parses custom regex patterns from the Settings tab text area."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        text = ext._customRegexArea.getText()
        new_regexs = []
        errors = []
        line_num = 0
        for line in text.split("\n"):
            line_num = line_num + 1
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                errors.append("Line %d: invalid format (expected name|regex)" % line_num)
                continue
            name = parts[0].strip()
            pattern = parts[1].strip()
            if not name or not pattern:
                errors.append("Line %d: empty name or pattern" % line_num)
                continue
            try:
                re.compile(pattern)
            except Exception as e:
                errors.append("Line %d: invalid regex: %s" % (line_num, str(e)))
                continue
            new_regexs.append((name, pattern))

        ext._lock.acquire()
        try:
            ext._custom_regexs = new_regexs
        finally:
            ext._lock.release()

        if errors:
            ext._log("[!] Custom regex errors:\n" + "\n".join(errors))
        ext._log("[*] Applied %d custom regex patterns" % len(new_regexs))
        ext._updateStatus("Applied %d custom patterns" % len(new_regexs))


class ClearActionListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        ext._lock.acquire()
        try:
            ext._tableModel.setRowCount(0)
            ext._row_count = 0
            ext._seen.clear()
            ext._http_messages.clear()
            ext._value_sources.clear()
            ext._severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
            ext._countLabel.setText("  Results: 0")
            ext._updateStatsLabel()
            ext._filterCountLabel.setText("")
            ext._requestViewer.setMessage(None, True)
            ext._responseViewer.setMessage(None, False)
            ext._matchViewer.setText(None)
        finally:
            ext._lock.release()


class ExportActionListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export JSReconRadar Results to CSV")
        result = chooser.showSaveDialog(self._extender._panel)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path = file_path + ".csv"
            try:
                model = self._extender._tableModel
                with open(file_path, "w") as f:
                    # Write header
                    cols = []
                    for c in range(model.getColumnCount()):
                        cols.append(model.getColumnName(c))
                    f.write(",".join(cols) + "\n")
                    # Write rows
                    for r in range(model.getRowCount()):
                        row_data = []
                        for c in range(model.getColumnCount()):
                            val = str(model.getValueAt(r, c))
                            val = val.replace('"', '""')
                            row_data.append('"' + val + '"')
                        f.write(",".join(row_data) + "\n")
                print("[*] Exported %d results to %s" % (model.getRowCount(), file_path))
            except Exception as e:
                print("[!] Export failed: %s" % str(e))


class SeverityRenderer(DefaultTableCellRenderer):
    """Color-codes table rows based on severity level."""
    _COLORS = {
        "CRITICAL": Color(80, 0, 0),
        "HIGH": Color(80, 40, 0),
        "MEDIUM": Color(60, 60, 0),
        "INFO": None,
    }
    _FG_COLORS = {
        "CRITICAL": Color(255, 120, 120),
        "HIGH": Color(255, 180, 100),
        "MEDIUM": Color(255, 255, 130),
        "INFO": None,
    }

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            try:
                model_row = table.convertRowIndexToModel(row)
                severity = str(table.getModel().getValueAt(model_row, 1))
                bg = self._COLORS.get(severity)
                fg = self._FG_COLORS.get(severity)
                if bg is not None:
                    comp.setBackground(bg)
                    comp.setForeground(fg if fg else Color.WHITE)
                else:
                    comp.setBackground(table.getBackground())
                    comp.setForeground(table.getForeground())
            except Exception:
                comp.setBackground(table.getBackground())
                comp.setForeground(table.getForeground())
        return comp


class SeverityToggleListener(ActionListener):
    """Re-applies filters when severity toggle buttons are clicked."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        self._extender.applyFilters()


class FilterDocumentListener(DocumentListener):
    """Re-applies filters as user types in the search box."""
    def __init__(self, extender):
        self._extender = extender

    def insertUpdate(self, event):
        self._extender.applyFilters()

    def removeUpdate(self, event):
        self._extender.applyFilters()

    def changedUpdate(self, event):
        self._extender.applyFilters()


class TableMouseAdapter(MouseAdapter):
    """Handles right-click on the table to show popup menu (Feature 1)."""
    def __init__(self, extender):
        self._extender = extender

    def mousePressed(self, event):
        self._handlePopup(event)

    def mouseReleased(self, event):
        self._handlePopup(event)

    def _handlePopup(self, event):
        if event.isPopupTrigger():
            table = self._extender._table
            row = table.rowAtPoint(event.getPoint())
            if row >= 0:
                table.setRowSelectionInterval(row, row)
                self._extender._popupMenu.show(event.getComponent(), event.getX(), event.getY())


class TablePopupActionListener(ActionListener):
    """Handles right-click context menu actions (Feature 1)."""
    def __init__(self, extender, action):
        self._extender = extender
        self._action = action

    def actionPerformed(self, event):
        ext = self._extender
        try:
            row = ext._table.getSelectedRow()
            if row < 0:
                return
            model_row = ext._table.convertRowIndexToModel(row)
            url_str = str(ext._tableModel.getValueAt(model_row, 2))
            matched_value = str(ext._tableModel.getValueAt(model_row, 4))
            row_num = str(ext._tableModel.getValueAt(model_row, 0))
            severity = str(ext._tableModel.getValueAt(model_row, 1))

            if self._action == "copy_value":
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(matched_value), None)

            elif self._action == "copy_url":
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(url_str), None)

            elif self._action == "send_repeater":
                msg = ext._http_messages.get(row_num)
                if msg is not None:
                    http_service = msg.getHttpService()
                    host = http_service.getHost()
                    port = http_service.getPort()
                    useHttps = (http_service.getProtocol() == "https")
                    request = msg.getRequest()
                    ext._callbacks.sendToRepeater(host, port, useHttps, request, "JSReconRadar")

            elif self._action == "send_intruder":
                msg = ext._http_messages.get(row_num)
                if msg is not None:
                    http_service = msg.getHttpService()
                    host = http_service.getHost()
                    port = http_service.getPort()
                    useHttps = (http_service.getProtocol() == "https")
                    request = msg.getRequest()
                    ext._callbacks.sendToIntruder(host, port, useHttps, request)

            elif self._action == "exclude_domain":
                try:
                    from java.net import URL
                    parsed = URL(url_str)
                    domain = parsed.getHost().lower()
                    ext._excluded_domains.add(domain)
                    ext._log("[*] Excluded domain: %s" % domain)
                except Exception:
                    pass

            elif self._action == "mark_fp":
                # Feature 6: Mark as False Positive
                ext._false_positive_values.add(matched_value)
                # Update severity count
                ext._lock.acquire()
                try:
                    if severity in ext._severity_counts and ext._severity_counts[severity] > 0:
                        ext._severity_counts[severity] = ext._severity_counts[severity] - 1
                finally:
                    ext._lock.release()
                # Remove the row from table
                ext._tableModel.removeRow(model_row)
                ext._updateStatsLabel()
                ext._log("[*] Marked as false positive: %s" % matched_value[:80])

        except Exception:
            ext._log("[!] Popup action error: %s" % traceback.format_exc())


class SaveActionListener(ActionListener):
    """Save results to JSON file (Feature 5)."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        chooser = JFileChooser()
        chooser.setDialogTitle("Save JSReconRadar Results")
        result = chooser.showSaveDialog(ext._panel)
        if result == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".json"):
                file_path = file_path + ".json"
            try:
                model = ext._tableModel
                rows = []
                for r in range(model.getRowCount()):
                    row_obj = {
                        "num": str(model.getValueAt(r, 0)),
                        "severity": str(model.getValueAt(r, 1)),
                        "url": str(model.getValueAt(r, 2)),
                        "type": str(model.getValueAt(r, 3)),
                        "value": str(model.getValueAt(r, 4)),
                        "sources": str(model.getValueAt(r, 5)),
                        "timestamp": str(model.getValueAt(r, 6)),
                    }
                    rows.append(row_obj)
                save_data = {
                    "results": rows,
                    "false_positive_values": list(ext._false_positive_values),
                    "excluded_domains": list(ext._excluded_domains),
                }
                f = open(file_path, "w")
                try:
                    f.write(json.dumps(save_data, indent=2))
                finally:
                    f.close()
                ext._log("[*] Saved %d results to %s" % (len(rows), file_path))
            except Exception as e:
                ext._log("[!] Save failed: %s" % str(e))


class LoadActionListener(ActionListener):
    """Load results from JSON file (Feature 5)."""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        chooser = JFileChooser()
        chooser.setDialogTitle("Load JSReconRadar Results")
        result = chooser.showOpenDialog(ext._panel)
        if result == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            try:
                f = open(file_path, "r")
                try:
                    content = f.read()
                finally:
                    f.close()
                save_data = json.loads(content)

                # Clear existing data
                ext._lock.acquire()
                try:
                    ext._tableModel.setRowCount(0)
                    ext._row_count = 0
                    ext._seen.clear()
                    ext._http_messages.clear()
                    ext._value_sources.clear()
                    ext._severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
                finally:
                    ext._lock.release()

                # Restore FP values and excluded domains
                fp_vals = save_data.get("false_positive_values", [])
                ext._false_positive_values = set(fp_vals)
                excl_domains = save_data.get("excluded_domains", [])
                ext._excluded_domains = set(excl_domains)

                # Load rows
                rows = save_data.get("results", [])
                for row_obj in rows:
                    row_num = row_obj.get("num", "0")
                    severity = row_obj.get("severity", "INFO")
                    url = row_obj.get("url", "")
                    stype = row_obj.get("type", "")
                    value = row_obj.get("value", "")
                    sources = row_obj.get("sources", "1")
                    timestamp = row_obj.get("timestamp", "")
                    ext._tableModel.addRow([row_num, severity, url, stype, value, sources, timestamp])
                    ext._row_count = ext._row_count + 1
                    if severity in ext._severity_counts:
                        ext._severity_counts[severity] = ext._severity_counts[severity] + 1

                ext._countLabel.setText("  Results: %d" % ext._row_count)
                ext._updateStatsLabel()
                ext._log("[*] Loaded %d results from %s" % (len(rows), file_path))
            except Exception as e:
                ext._log("[!] Load failed: %s" % str(e))


class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._mime_type = self._helpers.analyzeResponse(self._requestResponse.getResponse()).getStatedMimeType()
        return

    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            myre = re.compile(regex, re.VERBOSE)
            encoded_resp = binascii.b2a_base64(self._helpers.bytesToString(response))
            decoded_resp = base64.b64decode(encoded_resp)
            decoded_resp = saxutils.unescape(decoded_resp)

            match_vals = myre.findall(decoded_resp)

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)

                try:
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))
                except Exception:
                    continue
        return (scan_issues)

    def findDirectRegEx(self, regex, issuename, issuelevel, issuedetail):
        """Like findRegEx but matches the pattern directly without a wrapper regex."""
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            myre = re.compile(regex)
            encoded_resp = binascii.b2a_base64(self._helpers.bytesToString(response))
            decoded_resp = base64.b64decode(encoded_resp)
            decoded_resp = saxutils.unescape(decoded_resp)

            match_vals = myre.findall(decoded_resp)

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)

                try:
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))
                except Exception:
                    continue
        return (scan_issues)


class SiteMapEntry(IHttpRequestResponse):
    """Minimal IHttpRequestResponse for adding URLs to the site map without sending requests."""
    def __init__(self, request, response, http_service):
        self._request = request
        self._response = response
        self._http_service = http_service
    def getRequest(self):
        return self._request
    def getResponse(self):
        return self._response
    def setRequest(self, message):
        self._request = message
    def setResponse(self, message):
        self._response = message
    def getComment(self):
        return None
    def setComment(self, comment):
        pass
    def getHighlight(self):
        return None
    def setHighlight(self, color):
        pass
    def getHttpService(self):
        return self._http_service
    def setHttpService(self, http_service):
        self._http_service = http_service


class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
