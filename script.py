import re
import csv
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
import mmap
import os
from typing import Iterator, Tuple, Dict, List
import logging
from datetime import datetime

# Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LogAnalyzer:
    def __init__(self, log_file: str, output_csv: str, failed_login_threshold: int = 10,
                 chunk_size: int = 50000, worker_processes: int = None):
        self.log_file = log_file
        self.output_csv = output_csv
        self.failed_login_threshold = failed_login_threshold
        self.chunk_size = chunk_size
        self.worker_processes = worker_processes or max(1, cpu_count() - 1)
        
        # Compile regex patterns for binary mode
        self.patterns = {
            'ip': re.compile(rb'(\d+\.\d+\.\d+\.\d+)'),
            'endpoint': re.compile(rb'"[A-Z]+ ([^"\s]+)'),
            'status': re.compile(rb'" (401) ')  
        }

    def process_chunk(self, chunk_pos: Tuple[int, int]) -> Tuple[Counter, Counter, Dict[str, int]]:
        chunk_start, chunk_end = chunk_pos
        ip_counter = Counter()
        endpoint_counter = Counter()
        failed_attempts = defaultdict(int)

        with open(self.log_file, 'rb') as f:
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                # Adjust chunk boundaries to complete lines
                if chunk_start > 0:
                    chunk_start = mm.find(b'\n', chunk_start - 1) + 1
                if chunk_end < mm.size():
                    chunk_end = mm.find(b'\n', chunk_end) + 1

                chunk_data = mm[chunk_start:chunk_end]
                
                for line in chunk_data.split(b'\n'):
                    if not line:
                        continue

                    # Extract IP
                    ip_match = self.patterns['ip'].search(line)
                    if not ip_match:
                        continue
                        
                    ip = ip_match.group(1).decode('utf-8')
                    ip_counter[ip] += 1

                    # Check for 401 status
                    if self.patterns['status'].search(line):
                        failed_attempts[ip] += 1

                    # Extract endpoint
                    endpoint_match = self.patterns['endpoint'].search(line)
                    if endpoint_match:
                        endpoint = endpoint_match.group(1).decode('utf-8')
                        endpoint_counter[endpoint] += 1

        return ip_counter, endpoint_counter, failed_attempts

    def analyze(self):
        """Main analysis method with parallel processing for large files."""
        start_time = datetime.now()
        logger.info(f"Starting analysis of {self.log_file}")

        # Generate chunk positions
        chunk_positions = list(self.get_file_chunks())
        total_chunks = len(chunk_positions)
        
        logger.info(f"Processing {total_chunks} chunks using {self.worker_processes} workers")

        # Process chunks in parallel
        with Pool(self.worker_processes) as pool:
            results = pool.map(self.process_chunk, chunk_positions)

        # Merge results
        logger.info("Merging results...")
        ip_counter, endpoint_counter, failed_attempts = self.merge_results(results)
        
        # Display and save results
        self.display_results(ip_counter, endpoint_counter, failed_attempts)
        self.generate_report(ip_counter, endpoint_counter, failed_attempts)

        duration = datetime.now() - start_time
        logger.info(f"Analysis completed in {duration}")
        
        return ip_counter, endpoint_counter, failed_attempts

    def get_file_chunks(self) -> Iterator[Tuple[int, int]]:
        """Generate chunk positions for memory-mapped file processing."""
        file_size = os.path.getsize(self.log_file)
        for chunk_start in range(0, file_size, self.chunk_size):
            chunk_end = min(chunk_start + self.chunk_size, file_size)
            yield chunk_start, chunk_end

    def merge_results(self, results: List[Tuple[Counter, Counter, Dict[str, int]]]) -> Tuple[Counter, Counter, Dict[str, int]]:
        """Merge results from all chunks."""
        ip_counter = Counter()
        endpoint_counter = Counter()
        failed_attempts = defaultdict(int)

        for ip_c, ep_c, fa in results:
            ip_counter.update(ip_c)
            endpoint_counter.update(ep_c)
            for ip, count in fa.items():
                failed_attempts[ip] += count

        return ip_counter, endpoint_counter, failed_attempts

    def display_results(self, ip_counts: Counter, endpoint_counts: Counter, failed_attempts: Dict[str, int]):
        """Display results in the terminal."""
        print("\nRequests per IP Address:")
        print(f"{'IP Address':<20}{'Request Count'}")
        print("-" * 40)
        for ip, count in ip_counts.most_common():
            print(f"{ip:<20}{count}")

        print("\nMost Accessed Endpoint:")
        print(f"{'Endpoint':<50}{'Access Count'}")
        print("-" * 70)
        if endpoint_counts:
            most_accessed = endpoint_counts.most_common(1)[0]
            print(f"{most_accessed[0]:<50}{most_accessed[1]}")

        print("\nSuspicious Activity:")
        print(f"{'IP Address':<20}{'Failed Login Count'}")
        print("-" * 40)
        for ip, count in failed_attempts.items():
            if count >= self.failed_login_threshold:
                print(f"{ip:<20}{count}")

    def generate_report(self, ip_counts: Counter, endpoint_counts: Counter, failed_attempts: Dict[str, int]):
        """Save results to CSV."""
        with open(self.output_csv, mode='w', newline='') as file:
            writer = csv.writer(file)
            
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.most_common():
                writer.writerow([ip, count])
            
            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            if endpoint_counts:
                most_accessed = endpoint_counts.most_common(1)[0]
                writer.writerow([most_accessed[0], most_accessed[1]])
            
            writer.writerow([])
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Attempts"])
            for ip, count in failed_attempts.items():
                if count >= self.failed_login_threshold:
                    writer.writerow([ip, count])

def main():
    # Configuration
    LOG_FILE = "sample.log"
    OUTPUT_CSV = "log_analysis_results.csv"
    FAILED_LOGIN_THRESHOLD = 10    #Adjust this to call suspicious login attempt if failed to login this number of times
    CHUNK_SIZE=10000000     #Adjust chunk size according to system memory for optimal performance,default is 50kbytes 
    # Create and run analyzer
    analyzer = LogAnalyzer(
        log_file=LOG_FILE,
        output_csv=OUTPUT_CSV,
        chunk_size=CHUNK_SIZE,
        failed_login_threshold=FAILED_LOGIN_THRESHOLD
    )
    
    analyzer.analyze()

if __name__ == "__main__":
    main()