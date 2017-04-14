/*

Copyright 2017 Continusec Pty Ltd

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

package assets

//go:generate go-bindata -pkg $GOPACKAGE -o assets.go www/

/*
    Needs:
	go get -u github.com/jteeuwen/go-bindata/...

	Just run:

	go generate

	in this directory to generate the static aassetss.
*/
