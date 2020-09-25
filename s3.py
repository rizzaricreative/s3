import requests, sys, os, base64, datetime, hashlib, hmac, json

class s3():

    def __init__(self):

        date                = datetime.datetime.utcnow()
        self.definitions    = {
                                'canonicaluri': ',
                                'region':       'eu-west-2',
                                'service':      's3',
                                'iso8601':      date.strftime('%Y%m%dT%H%M%SZ'),
                                'yyyymmdd':     date.strftime('%Y%m%d'),
                                'bucket':       os.environ.get(''),
                                'kmsid':        ',
                                'auth': {
                                    'accesskey': os.environ.get('AWS_ACCESS_KEY_ID'),
                                    'secretkey': os.environ.get('AWS_SECRET_ACCESS_KEY')
                                }
                            }

        if not self.definitions['auth']['accesskey'] or not self.definitions['auth']['secretkey'] or not self.definitions['bucket']:
            print("""
                Please export the following:
                AWS_BUCKET_PAYLOADLOGGING= 
                AWS_ACCESS_KEY_ID= e.g access key
                AWS_SECRET_ACCESS_KEY= e.g secret key
            """)
            exit(1)

    def canonicalrequest( self, verb, canonicaluri, canonicalquerystring, canonicalheaders, signedheaders, payloadhash ):

        return verb + '\n' + canonicaluri + '\n' + canonicalquerystring + '\n' + canonicalheaders + '\n' + signedheaders + '\n' + payloadhash

    def stringtosign( self, iso8601, scope, hexhashcanonicalrequest ):

        return 'AWS4-HMAC-SHA256' + '\n' + iso8601 + '\n' + scope + '\n' + hexhashcanonicalrequest

    def sign( self, key, message ):

        return hmac.new( key, message.encode("utf-8"), hashlib.sha256)

    def signingkey( self, accesskey, yyyymmdd, region, service ):

        datekey                 = self.sign(('AWS4' + accesskey).encode("utf-8"), yyyymmdd).digest()
        dateregionkey           = self.sign( datekey, region).digest()
        dateregionservicekey    = self.sign( dateregionkey, service ).digest()

        return self.sign( dateregionservicekey, 'aws4_request' ).digest()

    def signature( self, signingkey, stringtosign ):

        return self.sign(signingkey, stringtosign).hexdigest()

    def main(self):

        self.definitions['bucket']              = os.environ.get('AWS_BUCKET_PAYLOADLOGGING')
        self.definitions['host']                = self.definitions['bucket'] + '.s3.' + self.definitions['region'] + '.amazonaws.com'
        self.definitions['payloadhash']         = hashlib.sha256('welcome to s3'.encode('utf-8')).hexdigest()
        self.definitions['canonicalheaders']    = "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-amz-server-side-encryption:aws:kms\nx-amz-server-side-encryption-aws-kms-key-id:{}\n".format( self.definitions['host'],
                                                                                                                                                                                                    self.definitions['payloadhash'],
                                                                                                                                                                                                    self.definitions['iso8601'],
                                                                                                                                                                                                    self.definitions['kmsid'])
        self.definitions['signedheaders']       = 'host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id'
        self.definitions['scope']               = '{}/{}/{}/aws4_request'.format( self.definitions['yyyymmdd'], self.definitions['region'], self.definitions['service'] )
        self.definitions['auth']                = {'accesskey': os.environ.get('AWS_ACCESS_KEY_ID'), 'secretkey': os.environ.get('AWS_SECRET_ACCESS_KEY')}

        canonicalrequest                        = self.canonicalrequest( 'PUT', self.definitions['canonicaluri'], "", self.definitions['canonicalheaders'], self.definitions['signedheaders'], self.definitions['payloadhash'] )
        self.definitions['canonicalrequest']    = { 'canonicalrequest': canonicalrequest, 'hexhashcanonicalrequest': hashlib.sha256(canonicalrequest.encode('utf-8')).hexdigest() }

        stringtosign                            = self.stringtosign( self.definitions['iso8601'], self.definitions['scope'], self.definitions['canonicalrequest']['hexhashcanonicalrequest'] ).strip()
        signingkey                              = self.signingkey( self.definitions['auth']['accesskey'], self.definitions['yyyymmdd'], self.definitions['region'], self.definitions['service'] )
        signature                               = self.sign( signingkey, stringtosign ).hexdigest()

        self.definitions['authorization']       = 'AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request,SignedHeaders={},Signature={}'.format(self.definitions['auth']['accesskey'], self.definitions['yyyymmdd'],
                                                    self.definitions['region'], self.definitions['service'], self.definitions['signedheaders'], signature)

        print(canonicalrequest)
        print()
        print(stringtosign)
        print()
        print(signingkey)
        print()
        print(signature)
        print()
        print(json.dumps(self.definitions, indent=4))

        headers = {'Authorization':self.definitions['authorization'],'Content-Type':'text/plain','Key':self.definitions['canonicaluri'],'x-amz-date':self.definitions['iso8601'],'x-amz-content-sha256':self.definitions['payloadhash'],
                    'x-amz-server-side-encryption':'aws:kms', 'x-amz-server-side-encryption-aws-kms-key-id':self.definitions['kmsid']}

        print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
        print('Request URL = ' + self.definitions['host'] + "/" + self.definitions['canonicaluri'] )

        r = requests.put('https://' + self.definitions['host'] + self.definitions['canonicaluri'], data='welcome to s3', headers=headers )

        print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
        print('Response code: %d\n' % r.status_code)
        print(r.text)

        print(r.request.headers)
        print(r.request.body)
        print(r.request.method)


s3().main()
