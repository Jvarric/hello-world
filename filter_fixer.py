#!/usr/bin/env python3
# FilterFixer
# Author: Eric Gillett <egillett@barracuda.com>
# Version: 1.9
# TODO change flask to return/accept JSON
# TODO: break remove_dupes function down into simpler functions
# Known Issues: Content filters containing a comma in the pattern are not parsed correctly,
#               will probably need to check for quotes around the pattern first

import re





#Jeff test edit


def deduplicate(filters):
    my_list = filters.splitlines()
    output, dupes, dupe_num = remove_dupes(my_list)
    return output, dupes, dupe_num


def generate_scope(scope):
    subject, header, body = scope
    scope_list = []
    scope_count = 0

    if subject == '1':
        scope_list.append('subject')
        scope_count += 1
    if header == '1':
        scope_list.append('headers')
        scope_count += 1
    if body == '1':
        scope_list.append('body')
        scope_count += 1
    scope_str = ','.join(scope_list)
#    if scope_count > 1:
#        scope_str = '"' + scope_str + '"'

    return scope_str


def reduce_scope(scope):
    scope_list = scope.split(',')
    subject, headers, body = 0, 0, 0

    for l in scope_list:
        if l == 'subject':
            subject = '1'
        if l == 'headers':
            headers = '1'
        if l == 'body':
            body = '1'
    scope_tuple = tuple(subject + headers + body)

    return scope_tuple


# Main dedupe function, called by almost everything else
# Really need to split this into multiple functions
def remove_dupes(filters):
    new, dupes = set(), set()
    output, esg_content_list, esg_attach_list, ess_content_list = [], [], [], []
    dupe_num = 0
    esg_content_dict, esg_attach_dict, ess_content_dict, ess_attach_dict, action_dict, scope_dict =\
        dict(), dict(), dict(), dict(), dict(), dict()
    warn = 0

    ip = re.compile(r'''
                   (?P<ip>                         # Start IP section
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                   (?P<netmask>                    # Start netmask section
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d).
                   (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                   (?:(?P<action>.+),)?            # Blocklist action
                   (?P<comment>.*)''', re.I | re.X)
    esg_content = re.compile(r'''
                            (?P<pattern>.+),
                            (?P<comment>.*),
                            (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                            (?P<out_action>Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                            (?P<subject>[01]),
                            (?P<header>[01]),
                            (?P<body>[01])''', re.I | re.X)
    esg_attach = re.compile(r'''
                           (?P<pattern>.+),
                           (?P<comment>.*),
                           (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                           (?P<out_action>Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                           (?P<archive>[01])''', re.I | re.X)
    ess_content = re.compile(r'''
                            (?P<pattern>.+),
                            (?P<action>Block|Allow|Quarantine|Encrypt),
                            (?P<scope>.+)''', re.I | re.X)
    ess_attach = re.compile(r'''
                           filename,
                           (?P<pattern>.+),
                           (?P<archive>[01]),
                           (?P<action>block|allow|quarantine),
                           (?P<comment>.*)''', re.I | re.X)

    for line in filters:
        line = line.lower()
        # Check if line is a content filter or attachment filter
        esg_content_filter = esg_content.match(line)
        esg_attach_filter = esg_attach.match(line)
        ess_content_filter = ess_content.match(line)
        ess_attach_filter = ess_attach.match(line)

        # Ignore filename at beginning of attachment filter
        if ess_attach_filter:
            pattern = (line.split(',', maxsplit=2)[1])
        else:
            pattern = (line.split(',', maxsplit=1)[0])

        if pattern == '':
            continue
        # Deduping IPs with subnets takes more effort than I have right now
        elif ip.match(line):
            output.append(line)
        elif esg_content_filter:
            # Check if pattern has been checked at least once before
            if pattern in esg_content_dict:
                dupes.add(pattern)
                dupe_num += 1
                # Compare new subject flag, if enabled, set enabled
                if esg_content_filter.group('subject') == '1':
                    esg_content_dict[pattern][3] = '1'
                # Compare new header flag, if enabled, set enabled
                if esg_content_filter.group('header') == '1':
                    esg_content_dict[pattern][4] = '1'
                # Compare new body flag, if enabled, set enabled
                if esg_content_filter.group('body') == '1':
                    esg_content_dict[pattern][5] = '1'
            else:
                # If new pattern, add to dict
                esg_content_dict[pattern] = [esg_content_filter.group('comment'),
                                             esg_content_filter.group('action'),
                                             esg_content_filter.group('out_action'),
                                             esg_content_filter.group('subject'),
                                             esg_content_filter.group('header'),
                                             esg_content_filter.group('body')]

        elif esg_attach_filter:
            # Check if pattern has been checked at least once before
            if pattern in esg_attach_dict:
                dupes.add(pattern)
                dupe_num += 1
                # Compare new subject flag, if enabled, set enabled
                if esg_attach_filter.group('archive') == '1':
                    esg_attach_dict[pattern][3] = '1'
            else:
                # If new pattern, add to dict
                esg_attach_dict[pattern] = [esg_attach_filter.group('comment'),
                                            esg_attach_filter.group('action'),
                                            esg_attach_filter.group('out_action'),
                                            esg_attach_filter.group('archive')]

        elif ess_attach_filter:
            if pattern in ess_attach_dict:
                dupes.add(pattern)
                dupe_num += 1
            else:
                # If new pattern, add to dict
                ess_attach_dict[pattern] = [ess_attach_filter.group('archive'),
                                            ess_attach_filter.group('action'),
                                            ess_attach_filter.group('comment')]

        elif ess_content_filter:
            if pattern in new:
                dupes.add(pattern)
                dupe_num += 1
            elif pattern in action_dict.keys():
                if ess_content_filter.group('action') != action_dict[pattern]:
                    if ess_content_filter.group('action') == 'encrypt':
                        action_dict[pattern] = 'encrypt'
                    elif ess_content_filter.group('action') == 'allow' and \
                            action_dict[pattern] == ('block' or 'quarantine'):
                        action_dict[pattern] = 'allow'
                    elif ess_content_filter.group('action') == 'block' and \
                            action_dict[pattern] == 'quarantine':
                        action_dict[pattern] = 'block'
                else:
                    pass
                dupes.add(pattern)
                dupe_num += 1
            else:
                # Add new pattern
                # ess_content_dict[pattern] = [ess_content_filter.group('action'), scope]
                action_dict[pattern] = ess_content_filter.group('action')
                scope_dict[pattern] = ess_content_filter.group('scope')
                new.add(pattern)

        elif pattern not in new:
            new.add(pattern)
            output.append(line)
        else:
            dupes.add(pattern)
            dupe_num += 1

    # Merge flags into string and convert dictonary to list
    for k, v in esg_content_dict.items():
        esg_content_dict[k] = ','.join(v)
    esg_content_list = ['{},{}'.format(k, v) for k, v in esg_content_dict.items()]
    for k, v in esg_attach_dict.items():
        esg_attach_dict[k] = ','.join(v)
    esg_attach_list = ['{},{}'.format(k, v) for k, v in esg_attach_dict.items()]
    ess_merge = [action_dict, scope_dict]
    ess_content_dict = {}
    for k in action_dict.keys():
        ess_content_dict[k] = ','.join(ess_content_dict[k] for ess_content_dict in ess_merge)
    ess_content_list = ['{},{}'.format(k, v) for k, v in ess_content_dict.items()]
    for k, v in ess_attach_dict.items():
        ess_attach_dict[k] = ','.join(v)
    ess_attach_list = ['filename,{},{}'.format(k, v) for k, v in ess_attach_dict.items()]

    # Add content and attachment lists in case each list has entries
    output.extend(esg_content_list)
    output.extend(esg_attach_list)
    output.extend(ess_content_list)
    output.extend(ess_attach_list)

    output = remove_empty(output)
    output = get_sorted(output)
    # Warn if there are duplicate BESS content filters
    if warn:
        return '\n'.join(filters), ['There are problems with content filter match scopes. Please '
                                    'check for dupes manually.'], 0

    if dupes == set():
        dupes = ['No duplicates found']
    return output, dupes, dupe_num


def remove_empty(my_list):
    clean_list = [x for x in my_list if x is not None]
    return clean_list


def get_sorted(my_list):
    # Only sort pattern before first comma
    my_list.sort(key=lambda x: x.split(',', maxsplit=1)[0])
    output = '\n'.join(my_list)
    if output == '':
        return 'No results.'
    else:
        return output


# Convert BESG action to BESS action where needed
def change_action(my_list):
    replacements = {'whitelist': 'allow', 'tag': 'quarantine'}
    replaced = []
    regex = re.compile('|'.join(map(re.escape, replacements)))

    # Iterate through list and replace actions as needed, appending the resulting line into replaced
    for line in my_list:
        replaced.append(regex.sub(lambda match: replacements[match.group(0)], line))

    return replaced


def ip_convert(filters):
    ip = re.compile(r'''
                    (?P<ip>                         # Start IP section
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                    (?P<netmask>                    # Start netmask section
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d).
                    (?:25[0-5]|2[0-4]\d|1?\d?\d)),
                    (?:(?P<action>.+),)?            # Blocklist action
                    (?P<comment>.*)''', re.I | re.X)
    my_list = []
    my_filters = filters.splitlines()

    for line in my_filters:
        match = ip.match(line)

        if match:
            if match.group('action') is None:
                action = 'exempt'
            else:
                # Pull action line into a string as lowercase
                action = ''.join(match.group('action'))
                action = action.lower()

            # Change tag or quarantine to block
            if (action == 'tag') or (action == 'quarantine'):
                action = 'block'

            # Join back into a single line matching BESS formatting
            match = ','.join(match.group('ip', 'netmask')) + ',' + action + \
                    ',' + ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)

    return output, dupes, dupe_num


def sender_convert(filters):
    sender_allow = re.compile(r'(?P<pattern>.+?),(?P<comment>.*)', re.I)
    sender_block = re.compile(r'(?P<pattern>.+?),(?P<comment>.*),'
                              r'(?P<action>block|quarantine|tag)', re.I)
    my_list = []
    my_filters = filters.splitlines()

    for line in my_filters:
        line = line.lower()
        if line.lower() == 'email address/domain,comment' or \
           line.lower() == 'email address/domain,comment,action':
            continue
        # Must check for blocks first since allow pattern matches block pattern as well
        match = sender_block.match(line)

        if match:
            # Convert action to string and drop case
            action = ''.join(match.group('action'))
            action = action.lower()

            # Change tag to quarantine
            if action == 'tag':
                action = 'quarantine'

            # Join back into a single line matching BESS formatting
            match = ''.join(match.group('pattern')) + ',' + action + ',' + \
                    ''.join(match.group('comment'))
            my_list.append(match)
        else:
            match = sender_allow.match(line)
            # Join back into a single line matching BESS formatting
            if not match:
                continue
            match = ''.join(match.group('pattern')) + ',exempt,' + \
                    ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)

    return output, dupes, dupe_num


def recip_convert(filters):
    recip_allow = re.compile(r'(?P<pattern>.+?),(?P<comment>.*)', re.I)
    recip_block = re.compile(r'(.+?),(.+),(.*)', re.I)
    my_list = []

    my_filters = filters.splitlines()

    for line in my_filters:
        line = line.lower()
        if line == 'email address/domain,comment' or \
           line == 'email address/domain,action,comment':
            continue
        # Must check for blocks first since allow pattern matches block pattern as well
        match = recip_block.match(line)

        if match:
            # Recipient blocks are not accepted
            continue

        match = recip_allow.match(line)
        if match:
            # Join pattern, action, and comment in proper order
            match = ''.join(match.group('pattern')) + ',exempt,' + \
                    ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)

    return output, dupes, dupe_num


def content_convert(filters):
    content = re.compile(r'''
                        (?P<pattern>.+),
                        (?P<comment>.*),
                        (?P<in_action>Block|Quarantine|Tag|Whitelist|Off),
                        (?P<out_action>Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                        (?P<subject>[01]),
                        (?P<headers>[01]),
                        (?P<body>[01])''', re.I | re.X)

    my_filters = filters.splitlines()
    inbound_filters, outbound_filters = [], []

    for line in my_filters:
        line = line.lower()
        match = content.match(line)

        if match:
            # Add filters into inbound/outbound lists based on actions
            if match.group('in_action') != ('off' or None):
                scope = generate_scope(match.group('subject', 'headers', 'body'))
                inbound_filters.append(','.join(match.group('pattern', 'in_action')) + ',' + scope)
            if match.group('out_action') != ('off' or 'redirect'):
                scope = generate_scope(match.group('subject', 'headers', 'body'))
                outbound_filters.append(','.join(match.group('pattern', 'out_action')) + ',' + scope)

    # Change action to BESS equivalent
    inbound_filters = change_action(inbound_filters)
    outbound_filters = change_action(outbound_filters)

    inbound, dupes_in, dupe_num_tmp = remove_dupes(inbound_filters)
    outbound, dupes_out, dupe_num = remove_dupes(outbound_filters)

    dupe_num += dupe_num_tmp

    return inbound, outbound, dupes_in, dupes_out, dupe_num


def attach_convert(filters):
    attach = re.compile(r'''
                        (?P<pattern>.+),
                        (?P<comment>.*),
                        (?P<action>Block|Quarantine|Tag|Whitelist|Off),
                        (?:Block|Quarantine|Tag|Whitelist|Off|Encrypt|Redirect),
                        (?P<archive>[01])''', re.I | re.X)
    my_list = []
    my_filters = filters.splitlines()

    for line in my_filters:
        line = line.lower()
        match = attach.match(line)

        if match:
            # Convert action to string and drop case
            action = ''.join(match.group('action'))
            action = action.lower()

            # Change action to BESS equivalent
            if action == 'tag':
                action = 'quarantine'
            elif action == 'whitelist':
                action = 'ignore'
            elif action == 'off':
                # Filter not enabled for inbound and should be ignored
                break

            # Combine into single line
            match = 'filename,' + ','.join(match.group('pattern', 'archive'))\
                    + ',' + action + ',' + ''.join(match.group('comment'))
            my_list.append(match)

    output, dupes, dupe_num = remove_dupes(my_list)

    return output, dupes, dupe_num


def main():
    pass


if __name__ == "__main__":
    main()
