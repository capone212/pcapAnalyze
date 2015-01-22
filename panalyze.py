import pyshark
import string
from collections import Counter

def stubData(packet):
	giopLayer = packet.giop
	stub = packet.data.giop_stub_data
	chars = [chr(int(x, base=16)) for x in stub.split(':')]
	rawString =  ''.join(chars)
	return filter(lambda x: x in string.printable, rawString)

def countResolves(captureFile):	
	print '-'*80
	cap = pyshark.FileCapture(captureFile,
	only_summaries=False,
	display_filter='giop.request_op contains "resolve_str" and giop.minor_version == 2')
	cap.load_packets();		
	print 'Resolves count ', len(cap)

	for item in Counter((stubData(x) for x in cap)).most_common():
		print item
	print ' '

def countRequests(captureFile):	
	print '-'*80
	cap = pyshark.FileCapture(captureFile,
	only_summaries=False,
	display_filter='giop.request_op')
	cap.load_packets();		
	print 'Requests count ', len(cap)

	for item in Counter((x.data.giop_request_op for x in cap)).most_common():
		print item
	print ' '

session = '/home/capone/work/python/pcapAnalyze/serviceStatusesOpt/first.pcapng'
countRequests(session)
countResolves(session)
print "exit"
