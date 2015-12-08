'''
Program that acts as a recursive DNS Caching Resolver.
Imports a server and client both using UDP sockets.

Uses the python programming language

@author: Joshua Engelsma
@version: 1.5
'''

import socket
from CacheObject import CacheObject
import datetime


class ResolverServer(object):
    
    def __init__(self, port=3490):
        self.address = ''
        self.port = 3490
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.serverSocket.bind(('',self.port))
        self.serverSocket.settimeout(120)
        print ('Listening to port {}'.format(self.port))
        rootServers = open('rootServers.txt')
        self.cache = {} #we start out with an empty cache, key will be name, values are IP address
        self.authcache = {}
        for line in rootServers:
            lineElements = line.strip().split()
            if len(lineElements) > 2:
                if lineElements[2] == 'A':
                    self.rootAddress = lineElements[3]
                    print('Root Server address is {}'.format(self.rootAddress))
                    break 
        
    def serve(self):
        running = True
        while running:
            try:
                print 'Waiting to receive a request from a client'
                data, clientAddress = self.serverSocket.recvfrom(3490)
    
                print 'received {} bytes from {}'.format(len(data), clientAddress)
                
                if data:
                    finalResponse = self.searchForAddress(data, self.rootAddress)
                    if finalResponse:
                        self.serverSocket.sendto(finalResponse, clientAddress)
                    else:
                        print('No response was received to send back to the client')
            except KeyboardInterrupt:
                print 'Shutting down server'
                self.serverSocket.close()
                break
            except socket.timeout:
                print 'dns resolver timing out... no requests'
                self.serverSocket.close()
                break
            
    def flipRecursionBitForRequests(self, data):
        '''
        Method finds byte that has recursion bit, and flips it
        @return the new byte array with the bit flipped
        '''
        byteArray = list(data)
        byteArray[2] = b'\0'
        newByteString = ''.join(byteArray)
        return newByteString
    
    def setFlagsForResponse(self, data):
        hexArray = [elem.encode("hex") for elem in data]
        hexArray[2] = '80'
        byteArray = [elem.decode("hex") for elem in hexArray]
        return ''.join(byteArray)
            
    def searchForAddress(self, data, address, port=53):
        '''
        Recursive method to find the ip address of a URL
        '''
        hexRequest = [elem.encode("hex") for elem in data] #convert the request to hex
        queryResults = self.parseQueries(hexRequest)
        initialQuery = ''.join(queryResults[0])
        data = self.flipRecursionBitForRequests(data)
        if initialQuery == 'printCache.com':
            for svnNames in self.cache:
                self.updateCacheTTL(svnNames, datetime.datetime.now(), self.cache)
            self.removeExpiredEntries(self.cache)
            for svn2Names in self.authcache:
                self.updateCacheTTL(svn2Names, datetime.datetime.now(), self.authcache)
            self.removeExpiredEntries(self.cache)
            print str(self.cache)
            print(str(self.authcache))
            return
        self.updateCacheTTL(initialQuery, datetime.datetime.now(), self.cache)
        self.removeExpiredEntries(self.cache)
        self.updateCacheTTL(initialQuery, datetime.datetime.now(), self.authcache) 
        self.removeExpiredEntries(self.authcache)
        if initialQuery in self.cache:
            if self.cache[initialQuery] != []:
                print("Using cached variables to get answer!!!")
                response = self.cache[initialQuery][0].bitString
                ttl = self.cache[initialQuery][0].ttl
                print('Time to live for this record is {}'.format(int(ttl)))
                idToChange = self.parseID(hexRequest)
                hexResponse = [elem.encode("hex") for elem in response]
                hexResponse[0] = idToChange[:2] #update the response id
                hexResponse[1] = idToChange[2:4]
                response = [elem.decode("hex") for elem in hexResponse]
                return ''.join(response)
        else:
            cachedAddress = None
            cachedAddress, cachedTTL = self.parseCache(initialQuery, self.authcache)
            if cachedAddress != None and cachedAddress != address:
                print("using cached variables to get closer to answer...ip {} !!!".format(cachedAddress))
                address = cachedAddress
                print('Time to live for this record is {}'.format(cachedTTL))
                
                
        sent = self.serverSocket.sendto(data, (address, 53))
        print 'sent {} bytes back to {}'.format(sent, address)
        print 'waiting for response from server {}'.format(address)
        response, address = self.serverSocket.recvfrom(3490)
        
        hexResponse = [elem.encode("hex") for elem in response] #receive packet
        
        nbrOfAnswers = int(hexResponse[6] + hexResponse[7], 16) #number of each layer
        nbrOfAuth = int(hexResponse[8] + hexResponse[9], 16)
        nbrOfAddi = int(hexResponse[10] + hexResponse[11], 16)
        print('Number Of Answers: {} Number of Authorizations: {} Number of Additional {}'.format(nbrOfAnswers, nbrOfAuth, nbrOfAddi))
        if nbrOfAnswers == 0 and (nbrOfAuth == 0 or nbrOfAddi == 0):
            return None #error here
        
        requestID = self.parseID(hexResponse) #handle the request ID
        
        queryResults = self.parseQueries(hexResponse) #handle the query
        query = ''.join(queryResults[0])
        currIndex = queryResults[1]
        currIndex += 4 #ignore query type and class (4 bytes)
        
        answersInfo = self.parseAnswerBytesStartingAtIndex(hexResponse, currIndex, nbrOfAnswers)
        answers = answersInfo[0]
        currIndex = answersInfo[1]
        authorizationInfo = self.parseAuthBytesStartingAtIndex(hexResponse, currIndex, nbrOfAuth)
        authorization = authorizationInfo[0]
        currIndex = authorizationInfo[1]
        additionalInfo = self.parseAdditionalBytesStartingAtIndex(hexResponse, currIndex, nbrOfAddi)
        additional = additionalInfo[0]
        currIndex = additionalInfo[1]
        
        self.cacheResponse(answers, authorization, additional, response)
                
        if len(answers[0]) == 0: #determine if we recurse or return final answer
            #need to call ourselves
            currServer = 0
            ip = ''
            while(True):
                topNameServer = authorization[currServer]['Address']
                validTypes = ['0001', '0002', '0005'] #TYPE: A, NS, CNAME are only types we handle
                for record in additional:
                    if record['NAME'] == topNameServer and record['TYPE'] in validTypes:
                        ip = record['Address']
                        break
                if ip != '': #we found an IP to ask for more info!!!
                    return self.searchForAddress(data, ip, 53)
                else:
                    currServer += 1
        else:
            if answers[0]['NAME'] == initialQuery:
                response = self.setFlagsForResponse(response)
                return response
            
    def cacheResponse(self, answers, authorization, additional, packet):
        '''
        Method looks through information from a server response and caches info for next time.
        '''
        
        if len(answers[0]) != 0 and answers[0]['NAME'] in self.cache:
            if self.cache[answers[0]['NAME']] == []:
                self.cache.pop(answers[0]['NAME'], None)
        if (len(answers[0]) != 0 and answers[0]['NAME'] not in self.cache): #we have some answers to parse.
            self.cache[answers[0]['NAME']] = []
            for answer in answers:
                name = answer['NAME']
                ipAdd = answer['Address']
                currTime = datetime.datetime.now()
                ttl = int(answer['TTL'], 16)
                cacheObj = CacheObject(name, ipAdd, currTime, ttl, packet)
                self.cache[name].append(cacheObj)
        if (len(authorization) != 0 and len(additional) != 0): #we have a next server to look for/cache
            validTypes = ['0001', '0002', '0005'] #TYPE: A, NS, CNAME are only types we handle
            if (len(authorization[0]) != 0 and authorization[0]['NAME'] in self.authcache):
                if self.authcache[authorization[0]['NAME']] == []:
                    self.authcache.pop(authorization[0]['NAME'], None)
            if (authorization[0]['NAME'] not in self.authcache):
                self.authcache[authorization[0]['NAME']] = []
                for auth in authorization:
                    name = auth['NAME']
                    authAddress = auth['Address']
                    ip = None
                    ttl = None
                    for addit in additional:
                        aname = addit['NAME']
                        if aname == authAddress and auth['TTL'] == addit['TTL'] and addit['TYPE'] in validTypes:
                            ip = addit['Address']
                            ttl = int(addit['TTL'], 16)
                            break
                    if ip != None and ttl != None:
                        cacheObj = CacheObject(name, ip, datetime.datetime.now(), ttl, packet)
                        self.authcache[name].append(cacheObj)
                
    def updateCacheTTL(self, cacheElement,currTime, cacheName):
        '''
        Method loops through all the cached contents
        and updates their time to live. If time to live is over, the 
        cached content is removed
        '''
        cacheObjects = None
        if cacheElement in cacheName:
            cacheObjects = cacheName[cacheElement]
        if cacheObjects:
            for cacheObj in cacheObjects:
                cacheObj.updateTimeToLive(datetime.datetime.now())

    def removeExpiredEntries(self, cacheName):
        '''
        removes any cache entries with less than 0 time remaining
        '''
        for key in cacheName:
            oldCacheObjects = cacheName[key]
            newCacheObjects = []
            for cacheObj in oldCacheObjects:
                if cacheObj.ttl > 0:
                    newCacheObjects.append(cacheObj)
            cacheName[key] = newCacheObjects            
                
    def parseCache(self, query, cacheName):
        '''
        Given a query, find the closest server to the query your cache contains
        '''
        newServerName = query
        while(True):
            if newServerName == '': #the query has no parts in our cache
                return (None, None)
            queryParts = newServerName.split('.')
            newSv = ''
            for part in queryParts:
                newSv += (part + '.')
            newSv = newSv[:-1] 
            if newSv in cacheName:
                if len(cacheName[newSv]) > 0: 
                    self.updateCacheTTL(newServerName, datetime.datetime.now(), cacheName)
                    self.removeExpiredEntries(cacheName)
                    return (cacheName[newServerName][0].ipAddress, cacheName[newServerName][0].ttl)
                else:
                    return (None, None)
            else:
                newServerName = ''
                queryParts.pop(0)
                for part in queryParts:
                    newServerName += (part + '.')
                newServerName = newServerName[:-1]
                    
            
    def parseAnswerBytesStartingAtIndex(self, hexArray, currIndex, nbrOfAnswers):
        '''
        Step two in parsing the packet... look up all the answers.
        '''
        allAnswers = []
        if nbrOfAnswers == 0:
            return ([{}], currIndex) #no answers, so return empty list with the new index spot
        for i in range(nbrOfAnswers):
            currRecord = {}
            nameInfo = self.getName(currIndex, hexArray)
            currRecord['NAME'] = nameInfo[0]
            currIndex = nameInfo[1]
            currRecord['TYPE'] = hexArray[currIndex] + hexArray[currIndex+1]
            currIndex += 2 #2 bytes for type
            currRecord['CLASS'] = hexArray[currIndex] + hexArray[currIndex + 1]
            currIndex += 2 #2 bytes for class
            currRecord['TTL'] = hexArray[currIndex] + hexArray[currIndex+1] + hexArray[currIndex+2] + hexArray[currIndex+3]
            currIndex += 4 #4 bytes for time to live
            currRecord['DL'] = int(hexArray[currIndex] + hexArray[currIndex+1], 16)
            currIndex += 2 #2 bytes to get the data length
            address = []
            for j in range(currRecord['DL']):
                address.append(hexArray[currIndex])
                currIndex += 1
            addressDec = []
            for hexVal in address:
                addressDec.append(int(hexVal, 16))
            addressString = ''
            for num in addressDec:
                addressString += str(num)
                addressString += '.'
            addressString = addressString[:-1]
            currRecord['Address'] = addressString
            allAnswers.append(currRecord)
        return (allAnswers, currIndex)
    
    def parseAuthBytesStartingAtIndex(self, hexArray, currIndex, nbrOfAuth):
        '''
        parse the auth layer
        '''
        allAuth = []
        for i in range(nbrOfAuth):
            currRecord = {}
            nameInfo = self.getName(currIndex, hexArray)
            currRecord['NAME'] = nameInfo[0]
            currIndex = nameInfo[1]
            currRecord['TYPE'] = hexArray[currIndex] + hexArray[currIndex+1]
            currIndex += 2 #2 bytes for type
            currRecord['CLASS'] = hexArray[currIndex] + hexArray[currIndex + 1]
            currIndex += 2 #2 bytes for class
            currRecord['TTL'] = hexArray[currIndex] + hexArray[currIndex+1] + hexArray[currIndex+2] + hexArray[currIndex+3]
            currIndex += 4 #4 bytes for time to live
            currRecord['DL'] = int(hexArray[currIndex] + hexArray[currIndex+1], 16)
            currIndex += 2 #2 bytes to get the data length
            nameInfo = self.getName(currIndex, hexArray)
            currRecord['Address'] = nameInfo[0]
            currIndex = nameInfo[1]
            allAuth.append(currRecord)
        return (allAuth, currIndex)
    
    def parseAdditionalBytesStartingAtIndex(self, hexArray, currIndex, nbrOfAddi):
        '''
        parse additional bytes
        '''
        allAddi = []
        for i in range(nbrOfAddi):
            currRecord = {}
            nameInfo = self.getName(currIndex, hexArray)
            currRecord['NAME'] = nameInfo[0]
            currIndex = nameInfo[1]
            currRecord['TYPE'] = hexArray[currIndex] + hexArray[currIndex+1]
            currIndex += 2 #2 bytes for type
            currRecord['CLASS'] = hexArray[currIndex] + hexArray[currIndex + 1]
            currIndex += 2 #2 bytes for class
            currRecord['TTL'] = hexArray[currIndex] + hexArray[currIndex+1] + hexArray[currIndex+2] + hexArray[currIndex+3]
            currIndex += 4 #4 bytes for time to live
            currRecord['DL'] = int(hexArray[currIndex] + hexArray[currIndex+1], 16)
            currIndex += 2 #2 bytes to get the data length
            address = []
            for j in range(currRecord['DL']):
                address.append(hexArray[currIndex])
                currIndex += 1
            addressDec = []
            for hexVal in address:
                addressDec.append(int(hexVal,16))
            addressString = ''
            for num in addressDec:
                addressString += str(num)
                addressString += '.'
            addressString = addressString[:-1]
            currRecord['Address'] = addressString
            allAddi.append(currRecord)
        return (allAddi, currIndex)
                
            
    def getName(self, currIndex, hexArray):
        '''
        Method used to return the name or address of the server.
        '''
        nameBytes = []
        if int(hexArray[currIndex], 16) == 192: #we have a pointer to deal with
            currIndex += 1
            offset = int(hexArray[currIndex],16)
            pointerContents = self.findPointerContents(hexArray, offset)[0]
            for pc in pointerContents:
                nameBytes.append(pc)
            currIndex += 1
        else: #no pointer thus far
            currNbrOfLettersToParse = int(hexArray[currIndex], 16)
            while currNbrOfLettersToParse != 0:
                for i in range(currNbrOfLettersToParse):
                    currIndex += 1
                    nameBytes.append(hexArray[currIndex])
                currIndex += 1
                currNbrOfLettersToParse = int(hexArray[currIndex], 16)
                nameBytes.append('.')
                if currNbrOfLettersToParse == 192:
                    currIndex += 1
                    offset = int(hexArray[currIndex],16)
                    pointerContents = self.findPointerContents(hexArray, offset)
                    for pc in pointerContents[0]:
                        nameBytes.append(pc)
                    nameBytes.append('.')
                    break
            currIndex += 1
            nameBytes.pop(len(nameBytes)-1)
        nameChars = []
        for hexVal in nameBytes:
            if hexVal == '.':
                nameChars.append('.')
            else:
                nameChars.append(hexVal.decode('hex'))
        nameString = ''.join(nameChars)
        return (nameString, currIndex)
            
    def parseID(self, hexArray):
        '''
        Returns the id of the request
        '''
        if len(hexArray) > 1:
            return hexArray[0] + hexArray[1]
        else:
            print 'Expected at least 2 bytes for id, but found {}'.format(len(hexArray))
            
    def parseQueries(self, hexArray):
        if len(hexArray) > 12:
            currIndex = 12
            queryArray = []
            currNbrOfLettersToParse = int(hexArray[currIndex], 16)
            while currNbrOfLettersToParse != 0:
                for i in range(currNbrOfLettersToParse):
                    currIndex += 1
                    queryArray.append(hexArray[currIndex].decode('hex'))
                currIndex += 1
                currNbrOfLettersToParse = int(hexArray[currIndex], 16)
                queryArray.append('.')
            currIndex += 1
            queryArray.pop(len(queryArray)-1)
            return (queryArray, currIndex)
            
        
    def findPointerContents(self, hexArray, offset):
        currIndex = offset
        contents = []
        currNbrOfLettersToParse = int(hexArray[currIndex], 16)
        while currNbrOfLettersToParse != 0:
            for i in range(currNbrOfLettersToParse):
                currIndex += 1
                contents.append(hexArray[currIndex])
            currIndex += 1
            currNbrOfLettersToParse = int(hexArray[currIndex], 16)
            contents.append('.')
            if currNbrOfLettersToParse == 192: #we have a pointer to a pointer!!!!
                currIndex += 1
                offset = int(hexArray[currIndex], 16)
                pointerContents = self.findPointerContents(hexArray, offset) #recursively search for contents
                for pc in pointerContents[0]:
                    contents.append(pc)
                currIndex += 1
                return(contents, currIndex)
        currIndex += 1
        contents.pop(len(contents)-1)
        return (contents, currIndex)
    

                
            
if __name__ == '__main__':
    ResolverServer().serve()
