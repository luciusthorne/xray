;;; xray.el --- Read the code of Linux commands with XRAY  -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: tools, languages, unix
;; URL: https://github.com/luciusthorne/xray

;; This file is not part of GNU Emacs.
;; SPDX-License-Identifier: Apache-2.0

;;; Commentary:

;; A front end for the `xray' command.  Every view opens in an *xray*
;; buffer where names are buttons:
;;
;;   RET on a function name   that function's code
;;   RET on a source file     the file's functions and text
;;   RET on PATH:LINE         visit the file at that line (when it is local)
;;   c                        call graph of the name at point
;;   g                        run the command again
;;
;; Commands:
;;
;;   M-x xray                 menu of everything below
;;   M-x xray-code            files, functions and code of a command
;;   M-x xray-code-at-point   the function under point, in this file
;;   M-x xray-callgraph       which function calls which
;;   M-x xray-report          overview of a command
;;   M-x xray-inspect         evidence graph: what it reaches, with proof
;;   M-x xray-why             proof chain from a command to a target
;;   M-x xray-reach           which programs reach a file or library
;;   M-x xray-serve           the interactive page in a browser
;;
;; Taint findings while you edit shell and Python scripts:
;;
;;   (add-hook 'sh-mode-hook #'xray-flymake-setup)
;;   (add-hook 'python-mode-hook #'xray-flymake-setup)

;;; Code:

(require 'button)
(require 'cl-lib)
(require 'json)
(require 'subr-x)

(defgroup xray nil
  "Read the code of Linux commands with XRAY."
  :group 'tools
  :prefix "xray-")

(defcustom xray-program "xray"
  "The xray executable."
  :type 'string)

(defcustom xray-taint-show-low nil
  "When non-nil, Flymake also shows low-severity taint findings."
  :type 'boolean)

(defvar-local xray--args nil
  "Arguments of the xray run shown in this buffer.")

(defvar-local xray--target nil
  "The command or file this buffer is about.")

;;; Running xray

(defun xray--command-line (args)
  (mapconcat #'shell-quote-argument (cons xray-program args) " "))

(defun xray--buffer-name (args)
  (format "*xray %s*" (string-join args " ")))

(defun xray-run (target &rest args)
  "Run xray on TARGET with ARGS and show the result in an *xray* buffer."
  (let* ((argv (cons target args))
         (buffer (get-buffer-create (xray--buffer-name argv))))
    (with-current-buffer buffer
      (let ((inhibit-read-only t))
        (erase-buffer)
        (xray-mode)
        (setq xray--args argv
              xray--target target)
        (insert (format "$ %s\n\n" (xray--command-line argv)))))
    (let ((process
           (make-process
            :name "xray"
            :buffer buffer
            :command (cons xray-program argv)
            :noquery t
            :filter #'xray--filter
            :sentinel #'xray--sentinel)))
      (process-put process 'xray-buffer buffer))
    (pop-to-buffer buffer)
    buffer))

(defun xray--filter (process output)
  (let ((buffer (process-buffer process)))
    (when (buffer-live-p buffer)
      (with-current-buffer buffer
        (let ((inhibit-read-only t))
          (save-excursion
            (goto-char (point-max))
            (insert (xray--strip-rules output))))))))

(defun xray--sentinel (process _event)
  (when (memq (process-status process) '(exit signal))
    (let ((buffer (process-buffer process)))
      (when (buffer-live-p buffer)
        (with-current-buffer buffer
          (let ((inhibit-read-only t))
            (xray-buttonize (point-min) (point-max))
            (unless (zerop (process-exit-status process))
              (save-excursion
                (goto-char (point-max))
                (insert (format "\n[xray exited with status %d]\n"
                                (process-exit-status process)))))))))))

(defun xray--strip-rules (text)
  "Drop XRAY's banner and box-drawing rules from TEXT."
  (replace-regexp-in-string "^\\(XRAY\\|[─═]+\\)\n" "" text))

(defun xray-output (&rest args)
  "Run xray synchronously with ARGS and return its standard output."
  (with-temp-buffer
    (apply #'call-process xray-program nil (list t nil) nil args)
    (buffer-string)))

;;; Buttons

(defconst xray--location-regexp
  "\\(/[^ \t\n():]+\\|[A-Za-z0-9_.@+-]+\\(?:/[^ \t\n():]+\\)+\\):\\([0-9]+\\)"
  "PATH:LINE as XRAY prints it.")

(defconst xray--arrow-regexp
  "^ *\\(?:→\\|←\\) \\([^ \n][^ \n]*\\)"
  "A call graph line: → NAME or ← NAME.")

(defconst xray--file-row-regexp
  "^  \\([^ \n]+\\.[A-Za-z+]+\\) +[0-9,]+ function(s)$"
  "A code map row: FILE  N function(s).")

(defconst xray--file-function-regexp
  "^ +[0-9]+  \\([^ \n].*\\)$"
  "A row of a file view: LINE  NAME.")

(define-button-type 'xray-location
  'action (lambda (button)
            (xray--visit (button-get button 'xray-file) (button-get button 'xray-line)))
  'help-echo "Visit this file at this line")

(define-button-type 'xray-function
  'action (lambda (button) (xray--code-in-context (button-get button 'xray-name)))
  'help-echo "Show this function's code (c: its call graph)")

(define-button-type 'xray-file
  'action (lambda (button) (xray--code-in-context (button-get button 'xray-name)))
  'help-echo "Show this file's functions and text")

(defun xray-buttonize (start end)
  "Turn names, files and locations between START and END into buttons."
  (save-excursion
    (goto-char start)
    (while (re-search-forward xray--location-regexp end t)
      (let ((file (match-string 1))
            (line (string-to-number (match-string 2))))
        (when (file-exists-p file)
          (make-text-button (match-beginning 0) (match-end 0)
                            'type 'xray-location 'xray-file file 'xray-line line))))
    (goto-char start)
    (while (re-search-forward xray--arrow-regexp end t)
      (unless (string-prefix-p "(" (match-string 1))
        (make-text-button (match-beginning 1) (match-end 1)
                          'type 'xray-function 'xray-name (match-string 1))))
    (goto-char start)
    (while (re-search-forward xray--file-row-regexp end t)
      (make-text-button (match-beginning 1) (match-end 1)
                        'type 'xray-file 'xray-name (match-string 1)))
    (goto-char start)
    (when (re-search-forward "function(s) compiled from this file:" end t)
      ;; Only the function list: it ends where the numbered source begins.
      (let ((stop (or (save-excursion (re-search-forward "^Source (" end t)) end)))
       (while (re-search-forward xray--file-function-regexp stop t)
        (let ((name (string-trim (match-string 1))))
          (unless (or (string-empty-p name) (string-match-p "  " name))
            (make-text-button (match-beginning 1) (match-end 1)
                              'type 'xray-function 'xray-name name))))))))

(defun xray--visit (file line)
  (find-file-other-window file)
  (goto-char (point-min))
  (forward-line (1- line)))

(defun xray--code-in-context (name)
  (if xray--target
      (xray-run xray--target "--code" name)
    (user-error "No command to read %s from" name)))

;;; Mode

(defvar xray-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "g") #'xray-rerun)
    (define-key map (kbd "c") #'xray-callgraph-at-point)
    (define-key map (kbd "TAB") #'forward-button)
    (define-key map (kbd "<backtab>") #'backward-button)
    map)
  "Keymap for `xray-mode'.")

(defvar xray-font-lock-keywords
  `(("^\\$ .*$" . font-lock-comment-face)
    ("^[A-Z][^\n:]*\\(?::\\|$\\)" . font-lock-keyword-face)
    (,xray--arrow-regexp 1 font-lock-function-name-face)
    ("\\[\\(observed\\|declared\\)\\]" 1 font-lock-constant-face)
    ("\\[\\(inferred\\)\\]" 1 font-lock-type-face)
    ("\\[\\(guessed\\)\\]" 1 font-lock-warning-face)))

(define-derived-mode xray-mode special-mode "XRAY"
  "Major mode for XRAY output.  Names and locations are buttons."
  (setq-local font-lock-defaults '(xray-font-lock-keywords t))
  (setq-local revert-buffer-function (lambda (&rest _) (xray-rerun)))
  (setq-local truncate-lines t))

(defun xray-rerun ()
  "Run this buffer's xray command again."
  (interactive)
  (unless xray--args
    (user-error "Not an xray buffer"))
  (apply #'xray-run xray--args))

(defun xray-callgraph-at-point ()
  "Show the call graph of the function named at point."
  (interactive)
  (let* ((button (button-at (point)))
         (name (or (and button (button-get button 'xray-name))
                   (thing-at-point 'symbol t))))
    (unless (and name xray--target)
      (user-error "No function at point"))
    (xray-run xray--target "--callgraph" name)))

;;; Choosing what to read

(defun xray--default-target ()
  (or (and buffer-file-name (file-executable-p buffer-file-name) buffer-file-name)
      (and buffer-file-name (string-match-p "\\.\\(el\\|scm\\|lisp\\|clj\\|py\\|sh\\|pl\\|rb\\|js\\|ts\\|lua\\)\\'"
                                            buffer-file-name)
           buffer-file-name)
      (thing-at-point 'filename t)))

(defun xray--read-target (prompt)
  (let ((default (xray--default-target)))
    (read-string (if default (format "%s (default %s): " prompt default) (format "%s: " prompt))
                 nil 'xray-target-history default)))

;;;###autoload
(defun xray-code (target &optional name)
  "Show the files, functions and code of TARGET, or the code of NAME in it."
  (interactive (let ((target (xray--read-target "Command or file")))
                 (list target (let ((name (read-string "Function or file (empty for the map): ")))
                                (unless (string-empty-p name) name)))))
  (if name (xray-run target "--code" name) (xray-run target "--code")))

;;;###autoload
(defun xray-code-at-point ()
  "Show the code of the function named at point, read from this buffer's file."
  (interactive)
  (unless buffer-file-name
    (user-error "This buffer has no file"))
  (let ((name (thing-at-point 'symbol t)))
    (unless name
      (user-error "No name at point"))
    (xray-run buffer-file-name "--code" name)))

;;;###autoload
(defun xray-callgraph (target &optional name)
  "Show which function calls which in TARGET, or both directions for NAME."
  (interactive (let ((target (xray--read-target "Command or file")))
                 (list target (let ((name (read-string "Function (empty for all): ")))
                                (unless (string-empty-p name) name)))))
  (if name (xray-run target "--callgraph" name) (xray-run target "--callgraph")))

;;;###autoload
(defun xray-report (target)
  "Show XRAY's overview of TARGET."
  (interactive (list (xray--read-target "Command or file")))
  (xray-run target "--report"))

;;;###autoload
(defun xray-inspect (target)
  "Show what TARGET reaches, with the proof for every link."
  (interactive (list (xray--read-target "Command or file")))
  (xray--run-verb "inspect" target))

;;;###autoload
(defun xray-why (target thing)
  "Show the proof chains from TARGET to THING."
  (interactive (list (xray--read-target "Command or file")
                     (read-string "File, command, library or package: ")))
  (xray--run-verb "why" target thing))

;;;###autoload
(defun xray-reach (thing)
  "Show which scanned programs reach THING."
  (interactive (list (read-string "File, command, library or package: ")))
  (xray--run-verb "reach" thing))

(defun xray--run-verb (verb target &rest args)
  "Run `xray VERB TARGET ARGS' (verbs come before their target)."
  (let* ((argv (append (list verb target) args))
         (buffer (get-buffer-create (xray--buffer-name argv))))
    (with-current-buffer buffer
      (let ((inhibit-read-only t)) (erase-buffer))
      (xray-mode)
      (setq xray--args nil xray--target target))
    (let ((process (make-process :name "xray" :buffer buffer :command (cons xray-program argv)
                                 :noquery t :filter #'xray--filter :sentinel #'xray--sentinel)))
      (ignore process))
    (with-current-buffer buffer
      (setq-local revert-buffer-function (lambda (&rest _) (apply #'xray--run-verb verb target args))))
    (pop-to-buffer buffer)))

;;;###autoload
(defun xray-serve (target)
  "Open XRAY's interactive page for TARGET in a browser."
  (interactive (list (xray--read-target "Command or file")))
  (make-process :name (format "xray-serve %s" target)
                :buffer (get-buffer-create "*xray serve*")
                :command (list xray-program target "--serve")
                :noquery t)
  (message "xray is opening %s in your browser" target))

;;;###autoload
(defun xray ()
  "Choose an XRAY view."
  (interactive)
  (let* ((actions '(("code: files, functions and code" . xray-code)
                    ("code of the function at point" . xray-code-at-point)
                    ("call graph" . xray-callgraph)
                    ("report" . xray-report)
                    ("inspect: what it reaches, with proof" . xray-inspect)
                    ("why: proof chain to a target" . xray-why)
                    ("reach: who reaches a file or library" . xray-reach)
                    ("serve: interactive page in a browser" . xray-serve)))
         (choice (completing-read "XRAY: " actions nil t)))
    (call-interactively (cdr (assoc choice actions)))))

;;; Flymake: taint findings

(defconst xray--severity
  '(("high" . :error) ("medium" . :warning) ("low" . :note) ("info" . :note)))

(defun xray-taint-diagnostics (report file)
  "Turn REPORT (parsed `xray taint --json') into (LINE TYPE MESSAGE) for FILE."
  (let (out)
    (dolist (item (append (alist-get 'findings report) nil))
      (let ((severity (alist-get 'severity item)))
        (when (or xray-taint-show-low (member severity '("high" "medium")))
          (cond
           ((and (equal (alist-get 'file item) file) (alist-get 'line item))
            (push (list (alist-get 'line item)
                        (alist-get severity xray--severity nil nil #'equal)
                        (format "%s (from %s; %s)" (alist-get 'detail item)
                                (string-join (append (alist-get 'sources item) nil) ", ")
                                (alist-get 'basis item)))
                  out))
           ((let ((first (car (append (alist-get 'chain item) nil))))
              (and first (equal (alist-get 'file first) file) (alist-get 'line first)))
            (let ((first (car (append (alist-get 'chain item) nil))))
              (push (list (alist-get 'line first)
                          (alist-get severity xray--severity nil nil #'equal)
                          (format "input reaches %s in %s:%s: %s" (alist-get 'sink item)
                                  (alist-get 'file item) (or (alist-get 'line item) "?")
                                  (alist-get 'detail item)))
                    out)))))))
    (nreverse out)))

(defvar-local xray--flymake-process nil)

(defun xray-flymake (report-fn &rest _args)
  "Flymake backend: `xray taint' on the saved file of this buffer."
  (when (process-live-p xray--flymake-process)
    (kill-process xray--flymake-process))
  (let ((source (current-buffer))
        (file (and buffer-file-name (file-truename buffer-file-name))))
    (if (not file)
        (funcall report-fn nil)
      (setq xray--flymake-process
            (make-process
             :name "xray-flymake" :noquery t :connection-type 'pipe
             :buffer (generate-new-buffer " *xray-flymake*")
             :command (list xray-program "taint" file "--json")
             :sentinel
             (lambda (process _event)
               (when (memq (process-status process) '(exit signal))
                 (unwind-protect
                     (when (and (buffer-live-p source)
                                (eq process (buffer-local-value 'xray--flymake-process source)))
                       (let* ((report (with-current-buffer (process-buffer process)
                                        (goto-char (point-min))
                                        (ignore-errors (json-read))))
                              (found (and report (xray-taint-diagnostics report file))))
                         (with-current-buffer source
                           (funcall report-fn
                                    (mapcar (lambda (entry)
                                              (let ((region (flymake-diag-region source (car entry))))
                                                (flymake-make-diagnostic source (car region) (cdr region)
                                                                         (nth 1 entry) (nth 2 entry))))
                                            found)))))
                   (kill-buffer (process-buffer process))))))))))

;;;###autoload
(defun xray-flymake-setup ()
  "Show `xray taint' findings in this buffer through Flymake."
  (require 'flymake)
  (add-hook 'flymake-diagnostic-functions #'xray-flymake nil t)
  (flymake-mode 1))

(provide 'xray)

;;; xray.el ends here
