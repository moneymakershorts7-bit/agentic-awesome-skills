# CodeQL Query Reference

## Example: Command Injection in Python (Custom Query)
```ql
import python
import semmle.python.security.dataflow.CommandInjectionCustomizations
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class CustomCmdInjectionConfig extends TaintTracking::Configuration {
  CustomCmdInjectionConfig() { this = "CustomCmdInjectionConfig" }
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandInjection::Sink
  }
}

from CustomCmdInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential command injection from $@.", source.getNode(), "user-controlled source"
```