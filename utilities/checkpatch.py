#!/usr/bin/env python
spellcheck_comments = False
                          'recirculation']
__parenthesized_constructs = 'if|for|while|switch|[_A-Z]+FOR_*EACH[_A-Z]*'
__regex_if_macros = re.compile(r'^ +(%s) \([\S][\s\S]+[\S]\) { \\' %
def check_comment_spelling(line):
    if not spell_check_dict or not spellcheck_comments:
    comment_words = filter_comments(line, True).replace(':', ' ').split(' ')
    for word in comment_words:
        if len(strword) and not spell_check_dict.check(strword.lower()):
            # skip words that start with numbers
            if strword.startswith(tuple('0123456789')):
     'check': lambda x: check_comment_spelling(x)},
    + ['[^<" ]<[^=" ]', '[^->" ]>[^=" ]', r'[^ !()/"]\*[^/]', '[^ !&()"]&',
       r'[^" +(]\+[^"+;]', '[^" -(]-[^"->;]', r'[^" <>=!^|+\-*/%&]=[^"=]',
       '[^* ]/[^* ]']
    for line in text.split('\n'):
        return -1
-S|--spellcheck-comments       Check C comments for possible spelling mistakes
def ovs_checkpatch_print_result(result):
    if result < 0:
    ovs_checkpatch_print_result(result)
                                       "spellcheck-comments",
        sys.exit(-1)
        elif o in ("-S", "--spellcheck-comments"):
                spellcheck_comments = True
            sys.exit(-1)
            ovs_checkpatch_print_result(result)
                status = -1
            sys.exit(-1)
        ovs_checkpatch_print_result(result)
            status = -1