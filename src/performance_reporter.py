import json
import statistics
import psutil
from datetime import datetime, timedelta
from typing import Dict, List

class PerformanceReporter:
    """Generates performance reports and analytics"""
    
    @staticmethod
    def generate_performance_report(bank_system):
        """Generate comprehensive performance report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_metrics': PerformanceReporter._get_system_metrics(),
            'crypto_performance': PerformanceReporter._analyze_metrics(bank_system.crypto_manager.performance_metrics),
            'protocol_performance': PerformanceReporter._analyze_metrics(bank_system.secure_protocol.performance_metrics),
            'auth_performance': PerformanceReporter._analyze_metrics(bank_system.mfa_auth.performance_metrics),
            'banking_performance': PerformanceReporter._analyze_metrics(bank_system.performance_metrics)
        }
        
        return report
    
    @staticmethod
    def _get_system_metrics():
        """Get system-level performance metrics"""
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_usage_mb': psutil.virtual_memory().used / 1024 / 1024,
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage_percent': psutil.disk_usage('.').percent
        }
    
    @staticmethod
    def _analyze_metrics(metrics: List[Dict]):
        """Analyze performance metrics for a component"""
        if not metrics:
            return {}
        
        operations = {}
        for metric in metrics:
            op_name = metric['operation']
            if op_name not in operations:
                operations[op_name] = []
            operations[op_name].append(metric['execution_time_ms'])
        
        analysis = {}
        for op_name, times in operations.items():
            analysis[op_name] = {
                'call_count': len(times),
                'avg_time_ms': statistics.mean(times),
                'min_time_ms': min(times),
                'max_time_ms': max(times),
                'p95_time_ms': statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times)
            }
        
        return analysis
    
    @staticmethod
    def print_real_time_dashboard(bank_system):
        """Print real-time performance dashboard"""
        report = PerformanceReporter.generate_performance_report(bank_system)
        
        print("\n" + "="*60)
        print("🏎️  REAL-TIME PERFORMANCE DASHBOARD")
        print("="*60)
        
        print(f"\n📊 System Resources:")
        print(f"  CPU Usage: {report['system_metrics']['cpu_percent']:.1f}%")
        print(f"  Memory: {report['system_metrics']['memory_percent']:.1f}%")
        print(f"  Disk: {report['system_metrics']['disk_usage_percent']:.1f}%")
        
        print(f"\n🔐 Cryptography Performance:")
        for op, stats in report['crypto_performance'].items():
            print(f"  {op}: {stats['avg_time_ms']:.2f}ms avg ({stats['call_count']} calls)")
        
        print(f"\n🔄 Protocol Performance:")
        for op, stats in report['protocol_performance'].items():
            print(f"  {op}: {stats['avg_time_ms']:.2f}ms avg ({stats['call_count']} calls)")
        
        print(f"\n🔑 Authentication Performance:")
        for op, stats in report['auth_performance'].items():
            print(f"  {op}: {stats['avg_time_ms']:.2f}ms avg ({stats['call_count']} calls)")
        
        print(f"\n🏦 Banking Operations Performance:")
        for op, stats in report['banking_performance'].items():
            print(f"  {op}: {stats['avg_time_ms']:.2f}ms avg ({stats['call_count']} calls)")
        
        print("="*60)
    
    @staticmethod
    def save_performance_report(bank_system, filename="performance_report.json"):
        """Save performance report to JSON file"""
        report = PerformanceReporter.generate_performance_report(bank_system)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Performance report saved to {filename}")
    
    @staticmethod
    def get_performance_summary(bank_system):
        """Get a quick performance summary"""
        report = PerformanceReporter.generate_performance_report(bank_system)
        
        summary = {
            'total_operations': sum(len(metrics) for metrics in [
                report['crypto_performance'],
                report['protocol_performance'], 
                report['auth_performance'],
                report['banking_performance']
            ]),
            'avg_crypto_time': statistics.mean([stats['avg_time_ms'] for stats in report['crypto_performance'].values()]) if report['crypto_performance'] else 0,
            'avg_protocol_time': statistics.mean([stats['avg_time_ms'] for stats in report['protocol_performance'].values()]) if report['protocol_performance'] else 0,
            'system_health': {
                'cpu': report['system_metrics']['cpu_percent'],
                'memory': report['system_metrics']['memory_percent'],
                'disk': report['system_metrics']['disk_usage_percent']
            }
        }
        
        return summary