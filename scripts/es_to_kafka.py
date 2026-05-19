#!/usr/bin/env python3
"""Bridge Elasticsearch documents into Kafka.

This script reads documents from an Elasticsearch index or index pattern and
publishes them into a Kafka topic. It is intended to route Zeek/Filebeat events
that have been indexed into Elasticsearch back into Kafka for downstream
consumers.

Usage:
    python es_to_kafka.py --host http://localhost:9200 --topic hpe-raw-events

If you run the new Zeek + Beats pipeline, use the `zeek-conn-*` index pattern.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Set

from confluent_kafka import Producer
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("es_to_kafka")

DEFAULT_ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DEFAULT_KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")
DEFAULT_INDEX = os.getenv("ES_INDEX_PATTERN", "zeek-conn-*")
DEFAULT_TOPIC = os.getenv("KAFKA_TOPIC", "hpe-raw-events")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read Elasticsearch docs and publish them to Kafka.")
    parser.add_argument("--es-url", default=DEFAULT_ES_URL,
                        help="Elasticsearch URL")
    parser.add_argument("--kafka-servers", default=DEFAULT_KAFKA_SERVERS,
                        help="Kafka bootstrap servers")
    parser.add_argument("--index", default=DEFAULT_INDEX,
                        help="Elasticsearch index or index pattern")
    parser.add_argument("--topic", default=DEFAULT_TOPIC,
                        help="Kafka topic to publish to")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Number of ES docs fetched per scroll batch")
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum number of documents to transfer (0 = no limit)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be sent without producing to Kafka")
    parser.add_argument("--watch", action="store_true",
                        help="Continuously poll ES for new documents (live mode)")
    parser.add_argument("--poll-interval", type=int, default=5,
                        help="Seconds between polls in --watch mode (default: 5)")
    return parser


def connect_elasticsearch(es_url: str) -> Elasticsearch:
    es = Elasticsearch(es_url, request_timeout=30)
    if not es.ping():
        raise RuntimeError(f"Could not connect to Elasticsearch at {es_url}")
    logger.info("Connected to Elasticsearch")
    return es


def connect_kafka(kafka_servers: str) -> Producer:
    producer = Producer({"bootstrap.servers": kafka_servers})
    logger.info(f"Connected to Kafka at {kafka_servers}")
    return producer


def iter_documents(
    es: Elasticsearch, index: str, batch_size: int, limit: int, watch: bool = False
) -> Iterator[Dict[str, Any]]:
    query = {"match_all": {}}
    if watch:
        query = {"range": {"@timestamp": {"gte": "now-30s"}}}
    scan_args = {
        "client": es,
        "index": index,
        "query": {"query": query},
        "size": batch_size,
        "scroll": "2m",
    }
    count = 0
    for hit in scan(**scan_args):
        if limit and count >= limit:
            break
        doc = hit.get("_source", {})
        doc["_es_index"] = hit.get("_index")
        doc["_es_id"] = hit.get("_id")
        yield doc
        count += 1


def delivery_report(err, msg) -> None:
    if err is not None:
        logger.error(f"Delivery failed for record {msg.key()}: {err}")
    else:
        logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}] @ {msg.offset()}")


# Graceful shutdown for watch mode
_running = True


def _handle_signal(sig, frame):
    global _running
    _running = False
    logger.info("Shutting down...")


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def transfer_batch(
    es: Elasticsearch,
    producer: Optional["Producer"],
    index: str,
    topic: str,
    batch_size: int,
    limit: int,
    dry_run: bool,
    seen_ids: Set[str],
    watch: bool = False,
) -> int:
    """Transfer one batch of documents from ES to Kafka, skipping already-seen IDs."""
    sent = 0
    for doc in iter_documents(es, index, batch_size, limit, watch):
        doc_id = doc.get("_es_id", "")
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)

        payload = json.dumps(doc, default=str)
        if dry_run:
            logger.info(f"Dry run: would send document id={doc_id} index={doc.get('_es_index')}")
        else:
            producer.produce(topic, payload.encode("utf-8"), callback=delivery_report)
            producer.poll(0)
        sent += 1

    if producer and sent > 0:
        producer.flush(timeout=30)
    return sent


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        es = connect_elasticsearch(args.es_url)
    except Exception as exc:
        logger.error(exc)
        return 1

    producer: Optional[Producer] = None
    if not args.dry_run:
        try:
            producer = connect_kafka(args.kafka_servers)
        except Exception as exc:
            logger.error(exc)
            return 1

    seen_ids: Set[str] = set()
    total_sent = 0

    if args.watch:
        # Continuous polling mode for live replay
        logger.info(f"Watch mode: polling {args.index} every {args.poll_interval}s")
        while _running:
            try:
                sent = transfer_batch(
                    es, producer, args.index, args.topic,
                    args.batch_size, args.limit, args.dry_run, seen_ids,
                    watch=True,
                )
                if sent > 0:
                    total_sent += sent
                    logger.info(
                        f"Transferred {sent} new documents "
                        f"(total: {total_sent}, tracked: {len(seen_ids)})"
                    )
            except Exception as exc:
                logger.warning(f"Poll error (will retry): {exc}")
            time.sleep(args.poll_interval)
    else:
        # One-shot mode (original behavior)
        total_sent = transfer_batch(
            es, producer, args.index, args.topic,
            args.batch_size, args.limit, args.dry_run, seen_ids,
        )

    logger.info(
        f"Transferred {total_sent} documents from "
        f"Elasticsearch index={args.index} to Kafka topic={args.topic}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
