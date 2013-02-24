using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using RavenDBMembership.Provider;
using System.Threading;
using NUnit.Framework;
using Raven.Client.Document;

namespace RavenDBMembership.Tests
{
    [TestFixture]
	public class RoleTests : InMemoryStoreTestcase
	{
        private string _appName = "MyApplication";
        private Role[] _testRoles = new Role[] { new Role("Role 1", null), new Role("Role 2", null), new Role("Role 3", null) };
        private string _testUserName = "Wilby";

        [SetUp]
        public void Setup() {
            RavenDBRoleProvider.DocumentStore = null;
        }



		[Test]
		public void StoreRole()
		{
			var newRole = new Role("Users", null);

			using (var store = NewInMemoryStore())
			{
				using (var session = store.OpenSession())
				{
					session.Store(newRole);
					session.SaveChanges();
				}

				Thread.Sleep(500);

				using (var session = store.OpenSession())
				{
					var role = session.Query<Role>().FirstOrDefault();
					Assert.NotNull(role);
					Assert.AreEqual("authorization/roles/users", role.Id.ToLower().ToLower());
				}
			}
		}

		[Test]
		public void StoreRoleWithApplicationName()
		{
			var newRole = new Role("Users", null);
			newRole.ApplicationName = _appName;

			using (var store = NewInMemoryStore())
			{
				using (var session = store.OpenSession())
				{
					session.Store(newRole);
					session.SaveChanges();
				}

				Thread.Sleep(500);

				using (var session = store.OpenSession())
				{
					var role = session.Query<Role>().FirstOrDefault();
					Assert.NotNull(role);
					Assert.AreEqual("authorization/roles/myapplication/users", role.Id.ToLower());
				}
			}
		}

		[Test]
		public void StoreRoleWithParentRole()
		{
			var parentRole = new Role("Users", null);
			var childRole = new Role("Contributors", parentRole);

			using (var store = NewInMemoryStore())
			{
				using (var session = store.OpenSession())
				{
					session.Store(parentRole);
					session.Store(childRole);
					session.SaveChanges();
				}

				Thread.Sleep(500);

				using (var session = store.OpenSession())
				{
					var roles = session.Query<Role>().ToList();
					Assert.AreEqual(2, roles.Count);
					var childRoleFromDb = roles.Single(r => r.ParentRoleId != null);
					Assert.AreEqual("authorization/roles/users/contributors", childRoleFromDb.Id.ToLower());
				}
			}
		}

		[Test]
		public void RoleExists()
		{			
			var newRole = _testRoles[0];
			newRole.ApplicationName = _appName;

			using (var store = NewInMemoryStore())
			{
				using (var session = store.OpenSession())
				{
					session.Store(newRole);
					session.SaveChanges();
				}

				Thread.Sleep(500);

				var provider = new RavenDBRoleProvider();
				RavenDBRoleProvider.DocumentStore = store;
				provider.ApplicationName = _appName;
				Assert.True(provider.RoleExists(_testRoles[0].Name));
			}
		}

		[Test]
		public void AddUsersToRoles()
		{
			var roles = _testRoles;
            for(int i = 0; i < roles.Length; i++) {
                roles[i].ApplicationName = _appName;
            }
			var user = new User();
			user.Username = _testUserName;
            user.ApplicationName = _appName;

            using (var store = NewInMemoryStore())
			{
                store.Initialize();
				using (var session = store.OpenSession())
				{
					foreach (var role in roles)
					{
						session.Store(role);
					}
					session.Store(user);
					session.SaveChanges();
				}

				var provider = new RavenDBRoleProvider();
				RavenDBRoleProvider.DocumentStore = store;
                provider.ApplicationName = _appName;
				provider.AddUsersToRoles(new [] { user.Username }, new [] { "Role 1", "Role 2" });

                using (var session = store.OpenSession())
                {
                    var u = session.Query<User>().Where(x => x.Username == user.Username && x.ApplicationName == user.ApplicationName).FirstOrDefault();
                    Assert.True(u.Roles.Any(x => x.ToLower().Contains("role 1")));
                    Assert.False(u.Roles.Any(x => x.ToLower().Contains("role 3")));

                }

				
			}
		}

		[Test]
		public void RemoveUsersFromRoles()
		{
			var roles = _testRoles;
			var user = new User();
			user.Username = _testUserName;
            user.ApplicationName = _appName;

			using (var store = NewInMemoryStore())
			{
                //Arrange
				using (var session = store.OpenSession())
				{
					foreach (var role in roles)
					{
                        role.ApplicationName = _appName;
						session.Store(role);
                        user.Roles.Add(role.Id.ToLower().ToLower());
					}
					session.Store(user);
					session.SaveChanges();
				}

				var provider = new RavenDBRoleProvider();
                provider.ApplicationName = _appName;
				RavenDBRoleProvider.DocumentStore = store;

                //Act
				provider.RemoveUsersFromRoles(new[] { user.Username }, new[] { "Role 1" });

                //Assert
                using (var session = store.OpenSession())
                {
                    var u = session.Query<User>().Where(x => x.Username == _testUserName && x.ApplicationName == _appName).FirstOrDefault();
                    Assert.False(u.Roles.Any(x => x.ToLower() == "role 1"));
                    Assert.True(u.Roles.Any(x => x.ToLower() != "role 2"));
                }
			}
		}

        [Test]
        public void FindUsersInRole_returns_users_in_role()
        {
            var roles = _testRoles;
            for (int i = 0; i < roles.Length; i++)
            {
                roles[i].ApplicationName = _appName;
            }
            var user = new User();
            user.Username = _testUserName;
            user.ApplicationName = _appName;

            using (var store = NewInMemoryStore())
            {
                //Arrange
                store.Initialize();
                using (var session = store.OpenSession())
                {
                    foreach (var role in roles)
                    {
                        session.Store(role);
                    }
                    session.Store(user);
                    session.SaveChanges();
                }

                var provider = new RavenDBRoleProvider();
                RavenDBRoleProvider.DocumentStore = store;
                provider.ApplicationName = _appName;
                provider.AddUsersToRoles(new[] { user.Username }, new[] { "Role 1", "Role 2" });

                //Act
                string[] users = provider.FindUsersInRole("Role 1", user.Username);             
   
                //Assert
                Assert.True(users.Contains(user.Username));
                
            }
        }

        [Test]
        public void GetRolesForUser_returns_roles_for_given_users()
        {
            var roles = _testRoles;
            for (int i = 0; i < roles.Length; i++)
            {
                roles[i].ApplicationName = _appName;
            }
            var user = new User();
            user.Username = _testUserName;
            user.ApplicationName = _appName;

            using (var store = NewInMemoryStore())
            {
                store.Initialize();
                using (var session = store.OpenSession())
                {
                    foreach (var role in roles)
                    {
                        session.Store(role);
                    }
                    session.Store(user);
                    session.SaveChanges();
                }

                var provider = new RavenDBRoleProvider();
                RavenDBRoleProvider.DocumentStore = store;
                provider.ApplicationName = _appName;
                provider.AddUsersToRoles(new[] { user.Username }, new[] { "Role 1", "Role 2" });

                string[] returnedRoles = provider.GetRolesForUser(user.Username);

                Assert.True(returnedRoles.Contains("Role 1") && returnedRoles.Contains("Role 2") && !returnedRoles.Contains("Role 3"));
                
            }
        }
	}
}
