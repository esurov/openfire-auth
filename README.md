This plugin enables custom authentication functionality for the Openfire chat servers. Authentication is JWT based, hence the plugin is self-contained.

It has other resources like clustering config file examples and a sql script to initialize the Openfire server settings.

The plugin implements JWT RS256 algorithm (private/public key). The JWT token should be passed instead of the user's password during the authentication.

It expects users to be stored in Redis (this part may be not used) and supports Hazelcast for Openfire caching.

Installation
------
1. Build with maven and copy the assembly jar from project target into the openfire/lib directory
3. Configure openfire/conf/openfire.xml

```	
	<provider>
  		<auth>
  			<className>org.jivesoftware.openfire.auth.HybridAuthProvider</className>
  		</auth>
  	</provider>
	<hybridAuthProvider>
  		<primaryProvider>
  			<className>org.jivesoftware.openfire.auth.DefaultAuthProvider</className>
  		</primaryProvider>
  		<secondaryProvider>
  			<className>com.i7.openfire.auth.AppAuthProvider</className>
  		</secondaryProvider>
  	</hybridAuthProvider>
```
4. Set the public key path in the i7.key.path property (see and example in the src/main/resources/properties.sql)
