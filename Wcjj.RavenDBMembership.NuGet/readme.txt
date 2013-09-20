RavenDBMembershp v2.0.2261
https://github.com/wilby/RavenDBMembership

CANNOT BE USED WITH DEFAULT MVC4 AccountController.
USE SecurityGuard.MVC4 or similar to manage your membership and roles 
https://www.nuget.org/packages/SecurityGuard.MVC4/
http://www.mvccentral.net/Story/Details/tools/kahanu/securityguard-nuget-package-for-asp-net-membership

//Connection String
//http://ravendb.net/docs/2.5/client-api/connecting-to-a-ravendb-datastore#using-a-connection-string 
<add name="RavenServer" connectionString="Url=http://localhost:8080;Database=webauth;" />

//Membership and Role Sections
//http://msdn.microsoft.com/en-us/library/6e9y4s5t%28v=vs.100%29.aspx
<membership defaultProvider="RavenDBMembership">
  <providers>
	<clear />
	<!--        <add name="AspNetSqlMembershipProvider" type="System.Web.Security.SqlMembershipProvider" connectionStringName="ApplicationServices"
		 enablePasswordRetrieval="false" enablePasswordReset="true" requiresQuestionAndAnswer="false" requiresUniqueEmail="false"
		 maxInvalidPasswordAttempts="5" minRequiredPasswordLength="6" minRequiredNonalphanumericCharacters="0" passwordAttemptWindow="10"
		 applicationName="/" />
		 -->
	<add name="RavenDBMembership" applicationName="MyApp" type="RavenDBMembership.Provider.RavenDBMembershipProvider, RavenDBMembership" 
	connectionStringName="RavenServer" enablePasswordRetrieval="true" enablePasswordReset="true" requiresQuestionAndAnswer="false" 
	maxInvalidPasswordAttempts="3" passwordAttemptWindow="30" enableEmbeddableDocumentStore="false" />
  </providers>
</membership>

<roleManager enabled="true" defaultProvider="RavenDBRole">
  <providers>
	<clear />
	<add name="RavenDBRole" applicationName="MyApp" connectionStringName="RavenServer" type="RavenDBMembership.Provider.RavenDBRoleProvider, 
	RavenDBMembership" enableEmbeddableDocumentStore="false" />
	<!--<add name="AspNetWindowsTokenRoleProvider" type="System.Web.Security.WindowsTokenRoleProvider" applicationName="/" />-->
  </providers>
</roleManager>