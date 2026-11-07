;;; xray-tests.el --- Tests for xray.el  -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: Apache-2.0

;;; Commentary:

;; emacs --batch -Q -L editors/emacs -l xray-tests.el -f ert-run-tests-batch-and-exit
;; XRAY_TEST_PROGRAM names the xray executable for the end-to-end test.

;;; Code:

(require 'ert)
(require 'xray)

(defun xray-tests--buttons ()
  "List (TYPE NAME-OR-FILE TEXT) for every button in the buffer."
  (let (out (pos (point-min)))
    (while (setq pos (next-button pos))
      (let ((button (button-at pos)))
        (push (list (button-type button)
                    (or (button-get button 'xray-name) (button-get button 'xray-file))
                    (button-label button))
              out)
        (setq pos (button-end button))))
    (nreverse out)))

(ert-deftest xray-buttons-callgraph-map-and-file-view ()
  (with-temp-buffer
    (insert "rg::search  (core/main.rs:107)\n"
            "  calls (2):\n"
            "    → globset::GlobSet::is_match  (globset/src/lib.rs:342)\n"
            "    ← rg::run  (core/main.rs:77)\n"
            "    ← (top level)  (line 9)\n"
            "Program: 52 file(s), 1,036 function(s)\n"
            "  core/flags/defs.rs                                         643 function(s)\n"
            "/src/x/main.rs\n"
            "2 function(s) compiled from this file:\n"
            "      43  rg::main\n"
            "      77  rg::run\n"
            "\n"
            "Source (60 lines, from debuginfod):\n"
            "   42  /// not a button\n")
    (xray-buttonize (point-min) (point-max))
    (should (equal (xray-tests--buttons)
                   '((xray-function "globset::GlobSet::is_match" "globset::GlobSet::is_match")
                     (xray-function "rg::run" "rg::run")
                     (xray-file "core/flags/defs.rs" "core/flags/defs.rs")
                     (xray-function "rg::main" "rg::main")
                     (xray-function "rg::run" "rg::run"))))))

(ert-deftest xray-buttons-local-locations-only ()
  (let ((file (make-temp-file "xray-test" nil ".sh" "a\nb\nc\n")))
    (unwind-protect
        (with-temp-buffer
          (insert (format "defined at %s:2\nand at /nonexistent/file.c:9\n" file))
          (xray-buttonize (point-min) (point-max))
          (should (equal (mapcar #'car (xray-tests--buttons)) '(xray-location)))
          (let ((button (button-at (next-button (point-min)))))
            (should (equal (button-get button 'xray-file) file))
            (should (= (button-get button 'xray-line) 2))))
      (delete-file file))))

(ert-deftest xray-taint-diagnostics-from-json ()
  (let* ((report (json-read-from-string
                  "{\"findings\": [
                     {\"file\": \"/s/a.sh\", \"line\": 4, \"severity\": \"high\", \"detail\": \"eval of input\",
                      \"sources\": [\"argv\"], \"basis\": \"inferred\", \"sink\": \"eval\", \"chain\": []},
                     {\"file\": \"/s/a.sh\", \"line\": 9, \"severity\": \"low\", \"detail\": \"low one\",
                      \"sources\": [\"env\"], \"basis\": \"inferred\", \"sink\": \"x\", \"chain\": []},
                     {\"file\": \"/s/helper.sh\", \"line\": 2, \"severity\": \"medium\", \"detail\": \"sh -c\",
                      \"sources\": [\"argv\"], \"basis\": \"inferred\", \"sink\": \"sh -c\",
                      \"chain\": [{\"file\": \"/s/a.sh\", \"line\": 7, \"detail\": \"passes $1\"}]}]}"))
         (xray-taint-show-low nil))
    (should (equal (xray-taint-diagnostics report "/s/a.sh")
                   '((4 :error "eval of input (from argv; inferred)")
                     (7 :warning "input reaches sh -c in /s/helper.sh:2: sh -c"))))))

(ert-deftest xray-end-to-end-callgraph-and-code ()
  (let ((program (getenv "XRAY_TEST_PROGRAM")))
    (skip-unless (and program (file-executable-p program)))
    (let* ((xray-program program)
           (script (make-temp-file "xray-test" nil ".sh"
                                   "#!/bin/sh\ngreet() {\n    echo hi\n}\ngreet\n"))
           (buffer (xray-run script "--callgraph")))
      (unwind-protect
          (with-current-buffer buffer
            (let ((process (get-buffer-process buffer)))
              (while (process-live-p process) (accept-process-output process 0.1)))
            (accept-process-output nil 0.1)
            (should (derived-mode-p 'xray-mode))
            (should (string-match-p "→ greet  (defined at line 2" (buffer-string)))
            (goto-char (point-min))
            (let ((button (button-at (next-button (point-min)))))
              (should (equal (button-get button 'xray-name) "greet"))
              ;; Following the button shows the function's code.
              (let ((code (with-current-buffer buffer (button-activate button) (current-buffer))))
                (with-current-buffer code
                  (let ((process (get-buffer-process code)))
                    (while (process-live-p process) (accept-process-output process 0.1)))
                  (should (string-match-p "greet() {" (buffer-string)))))))
        (delete-file script)))))

(provide 'xray-tests)

;;; xray-tests.el ends here
