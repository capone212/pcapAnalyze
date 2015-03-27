import pyshark
import string
from collections import Counter
from collections import namedtuple

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
	display_filter='giop.request_op and giop.request_op != "PutEvents"')
	cap.load_packets();		
	print 'Requests count ', len(cap)

	for item in Counter((x.data.giop_request_op for x in cap if hasattr(x.data, 'giop_request_op'))).most_common():
		print item
	print ' '

def measureResponseTime(captureFile):
	print '-'*80
	cap = pyshark.FileCapture(captureFile,
	only_summaries=False,
	display_filter='giop.type == "Reply" || giop.type == "Request"')
	cap.load_packets();		
	print 'Requests count ', len(cap)
	requests = dict()
	for item in cap:
		if not(item.data.giop_request_id in requests):
			requests[item.data.giop_request_id] = {}
		requests[item.data.giop_request_id][item.giop.type] = item 	
	print '-'*80
	sortedList = list()
	for rid, data in requests.iteritems():
		req = data['0']
		res = data['1']
		delta = (res.sniff_time - req.sniff_time).total_seconds();
		f = (delta, req)
		sortedList.append(f)
	sortedList.sort(key = lambda x: x[0])
	for i in sortedList:
		req = i[1];
		rid = req.data.giop_request_id
		print rid, req.data.giop_request_op, " starttime:", req.sniff_time.time(), " delta:", i[0]

		
		
		#requests[item.data.giop_request_id].req = 
	return
	# for item in Counter((x.data.giop_request_op for x in cap if hasattr(x.data, 'giop_request_op'))).most_common():
	# 	print item
	# print ' '

session = '/home/capone/work/python/pcapAnalyze/1.pcapng'
#countRequests(session)
#countResolves(session)
measureResponseTime(session)
print "exit"
