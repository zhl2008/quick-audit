#!/usr/bin/env python

import os
import sys
from config import *
import re

'''
level 0: normal shell 
level 1: specialized shell
level 2: obfuscated shell

'''

def audit_content(content,level):
	msg = ''
	if len(content) < content_thresold_value:
		msg += '||too short file'


	for r in tencent_webshell_rule_php:
		rule_type = r[0]
		rule_level = r[1]
		rule_id = r[2]
		rule = r[3]
		if level!=rule_level:
			continue
		tmp = re.search(rule,content)
		if tmp:
			match_content = tmp.group()
			if len(match_content) > 200:
				match_content = 'too long to show'
			msg += '||match rules: ' + match_content
			return (rule_type,str(rule_id),msg[2:])

		
	return False


def walk(scan_path,level):
	shell_num = 0
	scan_num = 0
	print '[*] scanning for ' + scan_path
	for p in os.walk(scan_path):
		for f in p[2]:
			filename = p[0] + '/' + f
			if os.path.splitext(filename)[-1][1:] in file_extensions:
				scan_num += 1
				res = audit_content(open(filename).read(),level)
				if res:
					print "[!]webshell found in " + filename + ':\t' + res[0] + ',' + res[2]
					shell_num += 1

	print '\nresults:'
	print '[!]total scan:' +str(scan_num)
	print '[!]total shell:' +str(shell_num)




if __name__ == '__main__':

	audit_content('<?php eval($_POST[222]);?>',0)
	walk('/tmp',0)
	
