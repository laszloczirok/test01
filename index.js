// TODO Ha nem json type, mennyiben módosul ez a lambda?


// v1.1.2
var https = require('https');
var zlib = require('zlib');
var crypto = require('crypto');

const endpoint = process.env.OPENSEARCH_ENDPOINT
const logFailedResponses = true;

let indexName = process.env.OPENSEARCH_INDEX_NAME


//var endpoint = 'vpc-testdomain-q74amxk6a2ytddtnyttip7qgve.eu-central-1.es.amazonaws.com';
// Set this to true if you want to debug why data isn't making it to
// your Elasticsearch cluster. This will enable logging of failed items
// to CloudWatch Logs.

exports.handler = function(input, context) {
    // decode input from base64
    let zippedInput = new Buffer.from(input.awslogs.data, 'base64');

    // decompress the input
    zlib.gunzip(zippedInput, function(error, buffer) {
        if (error) { context.fail(error); return; }

        // parse the input from JSON
        let awslogsData = JSON.parse(buffer.toString('utf8'));

        console.log(awslogsData)

        // transform the input to Elasticsearch documents
        let elasticsearchBulkData = transform(awslogsData);

        // skip control messages
        if (!elasticsearchBulkData) {
            console.log('Received a control message');
            context.succeed('Control message handled successfully');
            return;
        }

        // post documents to the Amazon Elasticsearch Service
        post(elasticsearchBulkData, function(error, success, statusCode, failedItems) {
            console.log('Response: ' + JSON.stringify({
                "statusCode": statusCode
            }));

            if (error) {
                logFailure(error, failedItems);
                context.fail(JSON.stringify(error));
            } else {
                console.log('Success: ' + JSON.stringify(success));
                context.succeed('Success');
            }
        });
    });
};

function transform(payload) {
    if (payload.messageType === 'CONTROL_MESSAGE') {
        return null;
    }

    let bulkRequestBody = '';

    payload.logEvents.forEach(function(logEvent) {
        let timestamp = new Date(1 * logEvent.timestamp);
        //TODO ráőfűzni a timestampet
        // index name format: cwl-YYYY.MM.DD
        if (indexName == undefined) {

            indexName = [
                'cwl-' + timestamp.getUTCFullYear(),              // year
                ('0' + (timestamp.getUTCMonth() + 1)).slice(-2),  // month
                ('0' + timestamp.getUTCDate()).slice(-2)          // day
            ].join('.');
        }


        let source = buildSource(logEvent.message, logEvent.extractedFields);
        source['@id'] = logEvent.id;
        source['@timestamp'] = new Date(1 * logEvent.timestamp).toISOString();
        source['@message'] = logEvent.message;
        source['@owner'] = payload.owner;
        source['@log_group'] = payload.logGroup;
        source['@log_stream'] = payload.logStream;

        let action = { "index": {} };
        action.index._index = indexName;
        action.index._type = payload.logGroup;
        action.index._id = logEvent.id;

        bulkRequestBody += [
            JSON.stringify(action),
            JSON.stringify(source),
        ].join('\n') + '\n';
    });
    return bulkRequestBody;
}

function buildSource(message, extractedFields) {
    if (extractedFields) {
        let source = {};

        for (let key in extractedFields) {
            if (extractedFields.hasOwnProperty(key) && extractedFields[key]) {
                let value = extractedFields[key];

                if (isNumeric(value)) {
                    source[key] = 1 * value;
                    continue;
                }

                let jsonSubString = extractJson(value);
                if (jsonSubString !== null) {
                    source['$' + key] = JSON.parse(jsonSubString);
                }

                source[key] = value;
            }
        }
        return source;
    }

    let jsonSubString = extractJson(message);
    if (jsonSubString !== null) {
        return JSON.parse(jsonSubString);
    }

    return {};
}

function extractJson(message) {
    let jsonStart = message.indexOf('{');
    if (jsonStart < 0) return null;
    let jsonSubString = message.substring(jsonStart);
    return isValidJson(jsonSubString) ? jsonSubString : null;
}

function isValidJson(message) {
    try {
        JSON.parse(message);
    } catch (e) { return false; }
    return true;
}

function isNumeric(n) {
    return !isNaN(parseFloat(n)) && isFinite(n);
}

function post(body, callback) {
    let requestParams = buildRequest(endpoint, body);

    let request = https.request(requestParams, function(response) {
        let responseBody = '';
        response.on('data', function(chunk) {
            responseBody += chunk;
        });

        response.on('end', function() {
            let info = JSON.parse(responseBody);
            let failedItems;
            let success;
            let error;

            if (response.statusCode >= 200 && response.statusCode < 299) {
                failedItems = info.items.filter(function(x) {
                    return x.index.status >= 300;
                });

                success = {
                    "attemptedItems": info.items.length,
                    "successfulItems": info.items.length - failedItems.length,
                    "failedItems": failedItems.length
                };
            }

            if (response.statusCode !== 200 || info.errors === true) {
                // prevents logging of failed entries, but allows logging
                // of other errors such as access restrictions
                delete info.items;
                error = {
                    statusCode: response.statusCode,
                    responseBody: info
                };
            }

            callback(error, success, response.statusCode, failedItems);
        });
    }).on('error', function(e) {
        callback(e);
    });
    request.end(requestParams.body);
}

function buildRequest(endpoint, body) {
    var endpointParts = endpoint.match(/^([^\.]+)\.?([^\.]*)\.?([^\.]*)\.amazonaws\.com$/);
    var region = endpointParts[2];
    var service = endpointParts[3];
    var datetime = (new Date()).toISOString().replace(/[:\-]|\.\d{3}/g, '');
    var date = datetime.substr(0, 8);
    var kDate = hmac('AWS4' + process.env.AWS_SECRET_ACCESS_KEY, date);
    var kRegion = hmac(kDate, region);
    var kService = hmac(kRegion, service);
    var kSigning = hmac(kService, 'aws4_request');

    var request = {
        host: endpoint,
        method: 'POST',
        path: '/_bulk',
        body: body,
        headers: {
            'Content-Type': 'application/json',
            'Host': endpoint,
            'Content-Length': Buffer.byteLength(body),
            'X-Amz-Security-Token': process.env.AWS_SESSION_TOKEN,
            'X-Amz-Date': datetime
        }
    };

    var canonicalHeaders = Object.keys(request.headers)
        .sort(function(a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; })
        .map(function(k) { return k.toLowerCase() + ':' + request.headers[k]; })
        .join('\n');

    var signedHeaders = Object.keys(request.headers)
        .map(function(k) { return k.toLowerCase(); })
        .sort()
        .join(';');

    var canonicalString = [
        request.method,
        request.path, '',
        canonicalHeaders, '',
        signedHeaders,
        hash(request.body, 'hex'),
    ].join('\n');

    var credentialString = [ date, region, service, 'aws4_request' ].join('/');

    var stringToSign = [
        'AWS4-HMAC-SHA256',
        datetime,
        credentialString,
        hash(canonicalString, 'hex')
    ] .join('\n');

    request.headers.Authorization = [
        'AWS4-HMAC-SHA256 Credential=' + process.env.AWS_ACCESS_KEY_ID + '/' + credentialString,
        'SignedHeaders=' + signedHeaders,
        'Signature=' + hmac(kSigning, stringToSign, 'hex')
    ].join(', ');

    return request;
}

function hmac(key, str, encoding) {
    return crypto.createHmac('sha256', key).update(str, 'utf8').digest(encoding);
}

function hash(str, encoding) {
    return crypto.createHash('sha256').update(str, 'utf8').digest(encoding);
}

function logFailure(error, failedItems) {
    if (logFailedResponses) {
        console.log('Error: ' + JSON.stringify(error, null, 2));

        if (failedItems && failedItems.length > 0) {
            console.log("Failed Items: " +
                JSON.stringify(failedItems, null, 2));
        }
    }
}

/* Példa entry
2022-09-21T16:32:28.157Z	1d78e028-d0e6-4891-a9ab-cc3cb55e8fa9	INFO	{
  messageType: 'DATA_MESSAGE',
  owner: '810257058449',
  logGroup: '/aws/lambda/logproducer',
  logStream: '2022/09/21/[$LATEST]f13b31f1036c41f580ed39a76bff6820',
  subscriptionFilters: [ 'forwarder-other-test' ],
  logEvents: [
    {
      id: '37103487875053007801048810680076249215593758334182096896',
      timestamp: 1663777938573,
      message: 'START RequestId: d913b59a-bccf-4482-92b6-44c9634d110a Version: $LATEST\n'
    },
    {
      id: '37103487875298315998232647534633142116592890310747881473',
      timestamp: 1663777938584,
      message: '2022-09-21T16:32:18.584Z\td913b59a-bccf-4482-92b6-44c9634d110a\tINFO\tTest log entry\n'
    },
    {
      id: '37103487876234947296570933706577642284044121493999058946',
      timestamp: 1663777938626,
      message: 'END RequestId: d913b59a-bccf-4482-92b6-44c9634d110a\n'
    },
    {
      id: '37103487876234947296570933706577642284044121493999058947',
      timestamp: 1663777938626,
      message: 'REPORT RequestId: d913b59a-bccf-4482-92b6-44c9634d110a\tDuration: 41.81 ms\tBilled Duration: 42 ms\tMemory Size: 128 MB\tMax Memory Used: 58 MB\t\n'
    }
  ]
}

 */