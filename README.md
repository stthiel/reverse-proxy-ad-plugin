Jenkins Reverse Proxy Authentication and Authorisation Plugin for MS-AD Forest

This changed version of the Reverse Proxy Plugin performs user authorization lookup in a slightly different manner
than the original plugin based on my needs for our environment.

1. User names forwarded by your proxy should include the domain name, e.g. domain\user.
2. In case you have a forest with multiple domains you should use your forest DN as the rootDN.
3. The domain name will be used to update the search base for every lookup dynamically, so users from different
   domains can login.
4. The search filter should be 'sAMAccountName={0}'
5. If an entry is found, all granted authorities (=groups) will be read from MS-specific attribute 'memberOf'
6. If the entry is a person, also 'displayName' and 'mail' will be used to update the Jenkins user settings on the fly.
7. The provided domain\user will become the ID of the Jenkins user as is! This is done to prevent multiple folders
   for the same user settings, e.g. \users\domain_user and \users\domain\user.
   The user settings folder is know \users\domain\user, always.

Limitations:

1. This is a simple hack to get our users from different domains of a huge forest authorized
   in an acceptable manner and speed.
2. I don't pretend to enhanced the original plugin, I only changed it to my needs.
3. Do not use MS-specific lookup in the Global Catalog. First this will break the plugin, second I experienced
   missing group memberships with it.
4. Groups as such to be used as Jenkins groups are not supported. All read groups are just used to build
   GrantedAuthorities for a user - with the group name only! However (AD) groups can be used to authorize users,
   just add the group name (only it) at the appropriate place (e.g. Matrix) in order to authorize members.
   BE AWARE, currently this could cause an sec issue if you have groups with the same name in different domains.

All other features of the original plugin remain, so have a look for further help there.
