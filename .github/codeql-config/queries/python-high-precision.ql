/**
 * @name High-Precision Python Security Issues
 * @description Custom queries that focus on real security vulnerabilities with minimal false positives
 * @kind problem
 * @id py/high-precision-security
 * @severity error
 */

import python
import semmle.python.security

// Only flag SQL injection in actual database operations
from CallExpr dbCall, DataFlow::Node source, DataFlow::Node sink
where
  // Real database calls
  (
    dbCall.getTarget().hasQualifiedName("sqlite3", "Cursor", "execute") or
    dbCall.getTarget().hasQualifiedName("sqlite3", "Connection", "execute") or
    dbCall.getTarget().hasQualifiedName("psycopg2", "cursor", "execute") or
    dbCall.getTarget().hasQualifiedName("MySQLdb", "cursor", "execute")
  ) and
  // User input flows to SQL query
  TaintTracking::localTaint(source, sink) and
  source.asExpr().(DataFlow::ReadNode) and
  sink.asExpr() = dbCall.getAnArgument() and
  // Exclude test files
  not source.getFile().getRelativePath().matches("%test%")
select sink, "Potential SQL injection from user input: $@", source, "user input"

// Only flag command injection in actual subprocess calls
from CallExpr cmdCall, DataFlow::Node source, DataFlow::Node sink
where
  // Real subprocess operations
  (
    cmdCall.getTarget().hasQualifiedName("subprocess", "run") or
    cmdCall.getTarget().hasQualifiedName("subprocess", "call") or
    cmdCall.getTarget().hasQualifiedName("os", "system") or
    cmdCall.getTarget().hasQualifiedName("os", "popen")
  ) and
  // User input flows to command
  TaintTracking::localTaint(source, sink) and
  source.asExpr().(DataFlow::ReadNode) and
  sink.asExpr() = cmdCall.getAnArgument() and
  // Exclude test files
  not source.getFile().getRelativePath().matches("%test%")
select sink, "Potential command injection from user input: $@", source, "user input"

// Only flag XSS in actual template rendering
from CallExpr templateCall, DataFlow::Node source, DataFlow::Node sink
where
  // Real template operations
  (
    templateCall.getTarget().hasQualifiedName("flask", "render_template_string") or
    templateCall.getTarget().hasQualifiedName("jinja2", "Template", "render")
  ) and
  // User input flows to template
  TaintTracking::localTaint(source, sink) and
  source.asExpr().(DataFlow::ReadNode) and
  sink.asExpr() = templateCall.getAnArgument() and
  // Exclude test files
  not source.getFile().getRelativePath().matches("%test%")
select sink, "Potential XSS from user input: $@", source, "user input"
