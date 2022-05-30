// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	endpoint, accessKey, secretKey string
	bucket, prefix, targetDir      string
	debug                          bool
	versions                       bool
	insecure                       bool
	corruptedOnly                  bool
)

const (
	targetFileName = "objectsinfo.txt"
)

// getMD5Sum returns MD5 sum of given data.
func getMD5Sum(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func main() {
	flag.StringVar(&endpoint, "endpoint", "https://play.min.io", "S3 endpoint URL")
	flag.StringVar(&accessKey, "access-key", "Q3AM3UQ867SPQQA43P2F", "S3 Access Key")
	flag.StringVar(&secretKey, "secret-key", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG", "S3 Secret Key")
	flag.StringVar(&bucket, "bucket", "", "Select a specific bucket")
	flag.StringVar(&prefix, "prefix", "", "Select a prefix")
	flag.BoolVar(&debug, "debug", false, "Prints HTTP network calls to S3 endpoint")
	flag.BoolVar(&versions, "versions", false, "Verify all versions")
	flag.BoolVar(&insecure, "insecure", false, "Disable TLS verification")
	flag.BoolVar(&corruptedOnly, "corrupted-only", false, "display corrupted entries only")
	flag.StringVar(&targetDir, "target-dir", "", fmt.Sprintf("Select a target directory to create the result file (%s)", targetFileName))
	flag.Parse()

	if endpoint == "" {
		log.Fatalln("Endpoint is not provided")
	}

	if accessKey == "" {
		log.Fatalln("Access key is not provided")
	}

	if secretKey == "" {
		log.Fatalln("Secret key is not provided")
	}

	if bucket == "" && prefix != "" {
		log.Fatalln("--prefix is specified without --bucket.")
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		log.Fatalln(err)
	}

	secure := strings.EqualFold(u.Scheme, "https")
	transport, err := minio.DefaultTransport(secure)
	if err != nil {
		log.Fatalln(err)
	}
	if insecure {
		// skip TLS verification
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	s3Client, err := minio.New(u.Host, &minio.Options{
		Creds:     credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:    secure,
		Transport: transport,
	})
	if err != nil {
		log.Fatalln(err)
	}

	f, err := os.OpenFile(filepath.Join(targetDir, targetFileName), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln("Could not open file path", filepath.Join(targetDir, targetFileName), err)
	}
	defer f.Close()

	datawriter := bufio.NewWriter(f)
	defer datawriter.Flush()

	if debug {
		s3Client.TraceOn(os.Stderr)
	}

	var buckets []string
	if bucket != "" {
		buckets = append(buckets, bucket)
	} else {
		bucketsInfo, err := s3Client.ListBuckets(context.Background())
		if err != nil {
			log.Fatalln(err)
		}
		for _, b := range bucketsInfo {
			buckets = append(buckets, b.Name)
		}
	}

	for _, bucket := range buckets {
		opts := minio.ListObjectsOptions{
			Recursive:    true,
			Prefix:       prefix,
			WithVersions: versions,
			WithMetadata: true,
		}

		// List all objects from a bucket-name with a matching prefix.
		for object := range s3Client.ListObjects(context.Background(), bucket, opts) {
			if object.Err != nil {
				log.Println("LIST error:", object.Err)
				continue
			}
			if object.IsDeleteMarker {
				continue
			}
			if _, ok := object.UserMetadata["X-Amz-Server-Side-Encryption-Customer-Algorithm"]; ok {
				continue
			}
			if v, ok := object.UserMetadata["X-Amz-Server-Side-Encryption"]; ok && v == "aws:kms" {
				continue
			}
			parts := 1
			multipart := false
			s := strings.Split(object.ETag, "-")
			switch len(s) {
			case 1:
				// nothing to do
			case 2:
				if p, err := strconv.Atoi(s[1]); err == nil {
					parts = p
				} else {
					log.Println("ETAG: wrong format:", err)
					continue
				}
				multipart = true
			default:
				log.Println("Unexpected ETAG format", object.ETag)
				continue
			}

			var partsMD5Sum [][]byte
			for p := 1; p <= parts; p++ {
				opts := minio.GetObjectOptions{
					VersionID:  object.VersionID,
					PartNumber: p,
				}
				obj, err := s3Client.GetObject(context.Background(), bucket, object.Key, opts)
				if err != nil {
					log.Println("GET", bucket, object.Key, object.VersionID, "=>", err)
					continue
				}
				h := md5.New()
				if _, err := io.Copy(h, obj); err != nil {
					log.Println("MD5 calculation error:", bucket, object.Key, object.VersionID, "=>", err)
					continue
				}
				partsMD5Sum = append(partsMD5Sum, h.Sum(nil))
			}

			corrupted := false
			if !multipart {
				md5sum := fmt.Sprintf("%x", partsMD5Sum[0])
				if md5sum != object.ETag {
					corrupted = true
				}
			} else {
				var totalMD5SumBytes []byte
				for _, sum := range partsMD5Sum {
					totalMD5SumBytes = append(totalMD5SumBytes, sum...)
				}
				s3MD5 := fmt.Sprintf("%x-%d", getMD5Sum(totalMD5SumBytes), parts)
				if s3MD5 != object.ETag {
					corrupted = true
				}
			}

			getNonEmptyVersionID := func(versionID string) string {
				if versionID == "" {
					return "null"
				}
				return versionID
			}

			var str string
			if corrupted {
				str = fmt.Sprintf("%s, %s, %s, %t\n", bucket, object.Key, getNonEmptyVersionID(object.VersionID), object.IsDeleteMarker)
			} else {
				if !corruptedOnly {
					str = fmt.Sprintf("%s, %s, %s, %t\n", bucket, object.Key, getNonEmptyVersionID(object.VersionID), object.IsDeleteMarker)
				}
			}
			if str != "" {
				if _, err := datawriter.WriteString(str); err != nil {
					log.Println("Error writing object to file:", bucket, object.Key, object.VersionID, err)
				}
			}
		}
	}
}
