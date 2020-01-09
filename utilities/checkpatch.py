#!/usr/bin/env python3
EXIT_FAILURE = 1
spellcheck = False
                          'recirculation', 'linux', 'afxdp', 'promisc', 'goto',
                          'misconfigured', 'misconfiguration', 'checkpatch',
                          'debian', 'travis', 'cirrus', 'appveyor', 'faq',
                          'erspan', 'const', 'hotplug', 'addresssanitizer',
                          'ovsdb', 'dpif', 'veth', 'rhel', 'jsonrpc', 'json',
                          'syscall', 'lacp', 'ipf', 'skb', 'valgrind']
__parenthesized_constructs = 'if|for|while|switch|[_A-Z]+FOR_*EACH[_A-Z0-9]*'
__regex_if_macros = re.compile(r'^ +(%s) \([\S]([\s\S]+[\S])*\) { +\\' %
def check_spelling(line, comment):
    if not spell_check_dict or not spellcheck:
    words = filter_comments(line, True) if comment else line
    words = words.replace(':', ' ').split(' ')

    for word in words:
        if (len(strword)
                and not spell_check_dict.check(strword.lower())
                and not spell_check_dict.check(word.lower())):
            # skip words containing numbers
            if any(check_char.isdigit() for check_char in strword):
     'check': lambda x: check_spelling(x, True)},
    + [r'[^<" ]<[^=" ]',
       r'[^\->" ]>[^=" ]',
       r'[^ !()/"]\*[^/]',
       r'[^ !&()"]&',
       r'[^" +(]\+[^"+;]',
       r'[^" \-(]\-[^"\->;]',
       r'[^" <>=!^|+\-*/%&]=[^"=]',
       r'[^* ]/[^* ]']
    for line in text.splitlines():
            elif spellcheck:
                check_spelling(line, False)

            # "sparse" includes could be copy-pasted from different sources
            # like DPDK or Linux and could contain workarounds not suitable
            # for a common style.
            if current_file.startswith('include/sparse'):
                continue
            if current_file.startswith('utilities/bugtool'):
                continue
        return EXIT_FAILURE
-S|--spellcheck                Check C comments and commit-message for possible
                               spelling mistakes
def ovs_checkpatch_print_result():
    if __errors or __warnings:
    ovs_checkpatch_print_result()
                                       "spellcheck",
        sys.exit(EXIT_FAILURE)
        elif o in ("-S", "--spellcheck"):
                spellcheck = True
            sys.exit(EXIT_FAILURE)
            ovs_checkpatch_print_result()
                status = EXIT_FAILURE
            sys.exit(EXIT_FAILURE)
        ovs_checkpatch_print_result()
            status = EXIT_FAILURE