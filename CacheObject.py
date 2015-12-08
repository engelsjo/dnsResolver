'''
Object that holds cache information.

@author: Joshua Engelsma
@version: 1.0
'''

class CacheObject(object):
    
    def __init__(self, name, ipAddress, dateStored, ttl, packet):
        self.name = name #server name.. eg com
        self.ipAddress = ipAddress #ip addresses of server
        self.dateStored = dateStored #datetime
        self.ttl = ttl #milliseconds
        self.bitString = packet
        
    def updateTimeToLive(self, currTime):
        '''
        @param currTime: datetime for the time of cache access
        Whenever you get an item from your cache, update its time to live,
        and the current time as the time that the data was stored.
        '''
        secondsExpired = (currTime - self.dateStored).total_seconds()
        self.dateStored = currTime
        self.ttl = int(self.ttl - secondsExpired)
        
    def __repr__(self):
        return ">>cache object: {} ip: {} ttl: {}<<".format(self.name, self.ipAddress, self.ttl)