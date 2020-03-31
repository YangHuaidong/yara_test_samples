#!/usr/bin/env python

import time, os
import sys
from datetime import timedelta
# from vt import *
from urllib.parse import urldefrag

sys.path.append(".")
# from common.Archive.settings import *

try:
    from tornado import httpclient, gen, ioloop, queues
except ImportError:
    from tornado import httpclient, gen, ioloop, queues

# vt = vtAPI()
count = 0

base_url = 'http://13.229.77.147:8000/?download='
concurrency = 10

@gen.coroutine
def download_file_from_url(hash, path):
    try:
        addr = base_url + hash
        response = yield httpclient.AsyncHTTPClient().fetch(addr, request_timeout=30000)
        f = open(os.path.join(path, hash), 'wb')
        f.write(response.body)
        f.close()
        global count
        count += 1
        print('[!] fetched %s %s' % (count, hash))

    except Exception as e:
        print('Exception: %s %s' % (e, addr))
        raise gen.Return([hash])


def remove_fragment(url):
    pure_url, frag = urldefrag(url)
    return pure_url


@gen.coroutine
def main(path, md5_path):
    q = queues.Queue()
    start = time.time()
    fetching, fetched = set(), set()

    @gen.coroutine
    def fetch_hash():
        # pauses until there is an item in the queue
        current_sample = yield q.get()
        try:
            if current_sample in fetching:
                return

            print('fetching %s' % current_sample)
            fetching.add(current_sample)
            urls = yield download_file_from_url(current_sample, path)
            fetched.add(current_sample)
            if urls:
                print('[!] Retry')
                for item in urls:
                    q.put(item)
        finally:
            q.task_done()

    @gen.coroutine
    def worker():
        while True:
            yield fetch_hash()

    with open(md5_path, 'r') as f:
        for item in f:
            print(item)
            q.put(item.rstrip())

    # Start workers, then wait for the work queue to be empty.
    for _ in range(concurrency):
        worker()
    yield q.join()

    print('Done in %d seconds, downloaded %s samples.' % (
        time.time() - start, len(fetched)))


if __name__ == '__main__':
    # keyword = 'microsoft:"Backdoor:Linux/Setag" and positives: 5+'
    # path = '/opt/LSH/YARA_sam/sampl'
    path = sys.argv[1]
    md5_path = sys.argv[2]

    io_loop = ioloop.IOLoop.current()
    io_loop.run_sync(lambda: main(path, md5_path))
