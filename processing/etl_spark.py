"""
Apache Spark PySpark Batch ETL Pipeline.
Ingests raw CSV flow logs, cleans schemas, applies columnar transformations,
and persists Silver (clean) and Gold (aggregated) Parquet datasets.
Can be executed via `spark-submit processing/etl_spark.py` or directly with python.
"""

import os
import sys

def run_spark_etl(
    input_csv: str = "data/raw/cicids2017_flows.csv",
    clean_dir: str = "data/clean",
    gold_dir: str = "data/gold"
):
    try:
        from pyspark.sql import SparkSession
        import pyspark.sql.functions as F
    except ImportError:
        print("[Spark ETL] PySpark not installed in environment. Skipping Spark job.")
        return

    print("[Spark ETL] Starting PySpark Session...")
    os.environ["JAVA_HOME"] = os.environ.get(
        "JAVA_HOME",
        "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"
    )

    spark = (
        SparkSession.builder
        .appName("ThreatIntel-BatchETL")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.driver.memory", "2g")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    print(f"[Spark ETL] Reading raw logs from {input_csv}...")
    logs = (
        spark.read.option("header", True)
        .option("inferSchema", True)
        .csv(input_csv)
    )

    # Normalize column names: strip spaces and replace with underscore
    clean_cols = [c.strip().replace(" ", "_").replace("/", "_") for c in logs.columns]
    logs = logs.toDF(*clean_cols)

    # Standardize attack indicator
    if "Label" in logs.columns:
        logs = logs.withColumn("is_attack", (F.col("Label") != "BENIGN").cast("int"))

    os.makedirs(clean_dir, exist_ok=True)
    silver_path = os.path.join(clean_dir, "logs.parquet")
    print(f"[Spark ETL] Writing Silver Layer Parquet to {silver_path}...")
    logs.write.mode("overwrite").parquet(silver_path)

    # Gold Layer: Attacks by type
    os.makedirs(gold_dir, exist_ok=True)
    if "Label" in logs.columns:
        gold_attacks = (
            logs.groupBy("Label")
            .agg(
                F.count("*").alias("count"),
                F.avg("Flow_Duration").alias("avg_duration_ms"),
                F.avg("Packet_Length_Mean").alias("avg_packet_len")
            )
            .orderBy(F.desc("count"))
        )
        gold_attacks.write.mode("overwrite").parquet(os.path.join(gold_dir, "attacks_by_type.parquet"))

    # Gold Layer: Top Ports hit by attackers
    if "Dst_Port" in logs.columns:
        gold_ports = (
            logs.filter(F.col("is_attack") == 1)
            .groupBy("Dst_Port")
            .agg(F.count("*").alias("attack_attempts"))
            .orderBy(F.desc("attack_attempts"))
            .limit(20)
        )
        gold_ports.write.mode("overwrite").parquet(os.path.join(gold_dir, "top_attacked_ports.parquet"))

    # Gold Layer: Hourly Attack Trends
    if "Hour" in logs.columns:
        gold_hourly = (
            logs.groupBy("Hour", "Label")
            .count()
            .orderBy("Hour")
        )
        gold_hourly.write.mode("overwrite").parquet(os.path.join(gold_dir, "hourly_attacks.parquet"))

    print("[Spark ETL] Pipeline completed successfully!")
    spark.stop()


if __name__ == "__main__":
    run_spark_etl()
