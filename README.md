# ASP.NET Membership and Role Provider for RavenDB 

The Solution contains the provider, a unit test project and an ASP.NET MVC 3 sample app.

This is a fork of the original project by Martijn Boland. The fork was created because Martijn's project was incomplete at the time. I spent the time completing the provider, during which I changed the unit test from xunit to nunit because I found xunit to be very slow in comparison.

After I made my changes I emailed Martijn to see if he would like the updated code to distribute on his blog but at that time he already placed the code on github and had Frank Schwiet contributing to the project. I decided to offer my code as an alternative implementation because I was using it and I new it to be complete.

__Wilby C. Jackson Jr.__

## Nuget Packages

### RavenDB 2.0
- Install-Package Wcjj.RavenDBMembership -Version 2.0.2261

### RavenDB 2.5
- Install-Package Wcjj.RavenDBMembership -Version 2.5.2700 

## ChangeLog

### 09/20/2013
- Updated RavenDB.Client and Embedded to version 2.5.2700. 
- Created Nuget Packages for 2.0 and 2.5
- Fixed a bug in ResetPassword that wasn't checking to see if QuestionAndAnswer were required.
- Directory tree cleanup

### 02/29/2012
Upgraded RavenDB to version 616. Had to remove raven from the id schema. This will break any existing applictions that have been using previous versions. RavenDB was updated which made the auto id's case sensitive and removed support for Contains Linq method.

### 02/22/2013
Fixed some reference and complation issues from the last merge.

Updated the connection string to utilize a webauth db in the sample app. It was using the system database.

Updated Raven client to v2.0.2261