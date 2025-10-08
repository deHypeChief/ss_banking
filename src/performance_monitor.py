import time
import psutil
import logging
from functools import wraps

class PerformanceMonitor:
    @staticmethod
    def measure_time(func):
        """Decorator to measure function execution time"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            result = func(*args, **kwargs)
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
            memory_used = end_memory - start_memory
            
            logging.info(f"⏱️ {func.__name__} took {execution_time:.2f}ms, Memory: {memory_used:.2f}MB")
            
            # Store metrics for reporting
            if hasattr(args[0], 'performance_metrics'):
                args[0].performance_metrics.append({
                    'operation': func.__name__,
                    'execution_time_ms': execution_time,
                    'memory_used_mb': memory_used,
                    'timestamp': time.time()
                })
            
            return result
        return wrapper