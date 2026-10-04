"""
Interactive Apache PySpark Demonstration Script.
Showcases distributed Spark DataFrame operations, execution plans (DAG),
and hosts the live Spark Web UI on http://localhost:4040.
"""

import os
import sys
import time

# Point to Java 17 Temurin JDK
os.environ["JAVA_HOME"] = os.environ.get(
    "JAVA_HOME",
    "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"
)

def main():
    print("""
  ======================================================================
     _____                  _      ______             _       _   
    / ____|                | |    |  ____|           (_)     | |  
   | (___  _ __   __ _ _ __| | __ | |__   ___  _ __ _ _  __ _| |_ 
    \___ \| '_ \ / _` | '__| |/ / |  __| / _ \| '__| | |/ _` | __|
    ____) | |_) | (_| | |  |   <  | |   | (_) | |  | | | (_| | |_ 
   |_____/| .__/ \__,_|_|  |_|\_\ |_|    \___/|_|  |_|_|\__, |\__|
          | |                                            __/ |    
          |_|                                           |___/     
  ======================================================================
  🔥 APACHE PYSPARK 3.5 DISTRIBUTED BIG DATA DEMONSTRATION
  ======================================================================
    """)

    try:
        from pyspark.sql import SparkSession
        import pyspark.sql.functions as F
    except ImportError:
        print("❌ PySpark not found in environment. Please activate venv: source venv/bin/activate")
        return

    print("🚀 Initializing Apache Spark Session in local[*] multi-core mode...")
    spark = (
        SparkSession.builder
        .appName("ForeSight-ThreatIntel-Spark")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.port", "4040")
        .getOrCreate()
    )

    sc = spark.sparkContext
    sc.setLogLevel("ERROR")

    print("\n✅ Spark Session Active!")
    print(f"   • Spark Version:   {spark.version}")
    print(f"   • Master Node:     {sc.master}")
    print(f"   • Application ID:  {sc.applicationId}")
    print(f"   • Spark Web UI:    http://localhost:4040  👈 (Open this in browser!)")
    print("-" * 70)

    # 1. Distributed Read
    csv_path = "data/raw/cicids2017_flows.csv"
    if not os.path.exists(csv_path):
        print(f"Creating sample data at {csv_path}...")
        from ingestion.load_logs import generate_flow_logs
        generate_flow_logs(num_records=10000, output_path=csv_path)

    print(f"\n📂 [Stage 1] Ingesting CSV dataset via Spark DataFrame Reader...")
    t0 = time.perf_counter()
    df = (
        spark.read.option("header", True)
        .option("inferSchema", True)
        .csv(csv_path)
    )
    # Clean column names
    clean_cols = [c.strip().replace(" ", "_").replace("/", "_") for c in df.columns]
    df = df.toDF(*clean_cols)
    read_time = time.perf_counter() - t0
    total_records = df.count()
    print(f"   Done in {read_time:.2f}s! Ingested {total_records:,} records across distributed partitions.")

    # 2. Distributed Schema
    print("\n📋 [Stage 2] Distributed Spark Schema (printSchema):")
    df.printSchema()

    # 3. Distributed Spark SQL Aggregation
    print("-" * 70)
    print("⚡ [Stage 3] Executing Distributed Spark SQL Aggregation (groupBy & agg)...")
    t0 = time.perf_counter()
    agg_df = (
        df.groupBy("Label")
        .agg(
            F.count("*").alias("Total_Flows"),
            F.round(F.avg("Flow_Duration"), 1).alias("Avg_Duration_ms"),
            F.round(F.avg("Total_Fwd_Packets"), 1).alias("Avg_Fwd_Pkts"),
            F.round(F.avg("Packet_Length_Mean"), 1).alias("Avg_Pkt_Len")
        )
        .orderBy(F.desc("Total_Flows"))
    )
    agg_df.show(truncate=False)
    agg_time = time.perf_counter() - t0
    print(f"   Query executed in {agg_time:.2f}s across {agg_df.rdd.getNumPartitions()} Spark partitions.")

    # 4. Spark Catalyst Physical Execution Plan (The Proof!)
    print("-" * 70)
    print("🧠 [Stage 4] Spark Catalyst Physical Execution Plan (df.explain):")
    agg_df.explain(True)

    # 5. Columnar Snappy Parquet Persistence
    print("-" * 70)
    parquet_out = "data/clean/spark_logs.parquet"
    print(f"💾 [Stage 5] Writing distributed Snappy Columnar Parquet to {parquet_out}...")
    df.write.mode("overwrite").parquet(parquet_out)
    print(f"   ✅ Successfully written to {parquet_out}")

    print("\n" + "=" * 70)
    print("🎉 PYSPARK DEMO COMPLETE!")
    print("=" * 70)
    print("🌐 SPARK WEB UI IS LIVE AT:  http://localhost:4040")
    print("   Open this URL in your browser to inspect:")
    print("   • Active Jobs & Event Timeline")
    print("   • Spark DAG (Directed Acyclic Graph) visualization")
    print("   • Worker Tasks & Shuffle Read/Write bytes")
    print("=" * 70)
    print("Press Ctrl+C (or wait 45 seconds) to terminate Spark session...\n")

    try:
        time.sleep(45)
    except KeyboardInterrupt:
        print("\nStopping Spark Session...")
    finally:
        spark.stop()
        print("Spark stopped cleanly.")


if __name__ == "__main__":
    main()
