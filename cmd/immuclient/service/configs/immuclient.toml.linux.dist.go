// +build linux darwin

/*
Copyright 2019-2020 vChain, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

// ConfigImmuClient ...
var ConfigImmuClient = []byte(`dir = "/var/lib/immuclient"
address = "0.0.0.0"
port = 3323
immudb-address = "127.0.0.1"
immudb-port = 3322
pidfile = "/var/lib/immudb/immuclient.pid"
logfile = "/var/log/immudb/immuclient.log"
mtls = false
detached = false
servername = "localhost"
audit-username = "immudb"
audit-password = "immudb"
pkey = "/etc/immudb/mtls/4_client/private/localhost.key.pem"
certificate = "/etc/immudb/mtls/4_client/certs/localhost.cert.pem"
clientcas = "/etc/immudb/mtls/2_intermediate/certs/ca-chain.cert.pem"`)
