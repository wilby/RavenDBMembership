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
					Assert.AreEqual("authorization/roles/users", role.Id);
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
					Assert.AreEqual("authorization/roles/myapplication/users", role.Id);
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
					Assert.AreEqual("authorization/roles/users/contributors", childRoleFromDb.Id);
				}
			}
		}

		[Test]
		public void RoleExists()
		{
			var appName = "APPNAME";
			var newRole = new Role("TheRole", null);
			newRole.ApplicationName = appName;

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
				provider.ApplicationName = appName;
				Assert.True(provider.RoleExists("TheRole"));
			}
		}

		[Test]
		public void AddUsersToRoles()
		{
			var roles = new Role[] { new Role("Role 1", null), new Role("Role 2", null), new Role("Role 3", null) };
            for(int i = 0; i < roles.Length; i++) {
                roles[i].ApplicationName = _appName;
            }
			var user = new User();
			user.Username = "UserWithRole1AndRole2";
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

				Assert.True(provider.IsUserInRole(user.Username, "Role 1"));
				Assert.False(provider.IsUserInRole(user.Username, "Role 3"));
			}
		}

		[Test]
		public void RemoveUsersFromRoles()
		{
			var roles = new Role[] { new Role("Role 1", null), new Role("Role 2", null), new Role("Role 3", null) };
			var user = new User();
			user.Username = "UserWithRole1AndRole2";

			using (var store = NewInMemoryStore())
			{
				using (var session = store.OpenSession())
				{
					foreach (var role in roles)
					{
						session.Store(role);
					}
					session.Store(user);
					session.SaveChanges();
				}

				Thread.Sleep(500);

				var provider = new RavenDBRoleProvider();
				RavenDBRoleProvider.DocumentStore = store;
				provider.AddUsersToRoles(new [] { user.Username }, new [] { "Role 1", "Role 2" });

				Assert.True(provider.IsUserInRole(user.Username, "Role 1"));
				Assert.True(provider.IsUserInRole(user.Username, "Role 2"));

				provider.RemoveUsersFromRoles(new[] { user.Username }, new[] { "Role 1" });

				Assert.False(provider.IsUserInRole(user.Username, "Role 1"));
				Assert.True(provider.IsUserInRole(user.Username, "Role 2"));
			}
		}
	}
}
