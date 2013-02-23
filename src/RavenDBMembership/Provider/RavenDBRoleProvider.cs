using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;
using System.Collections.Specialized;
using Raven.Client;
using System.IO;
using System.Configuration;
using System.Configuration.Provider;
using Raven.Client.Document;
using Raven.Client.Linq;
using Raven.Client.Embedded;


namespace RavenDBMembership.Provider
{
	public class RavenDBRoleProvider : RoleProvider
	{
		private const string ProviderName = "RavenDBRole";
		private static IDocumentStore _documentStore;

        
		public static IDocumentStore DocumentStore
		{
			get
			{
				if (_documentStore == null)
				{
					throw new NullReferenceException("The DocumentStore is not set. Please set the DocumentStore or make sure that the Common Service Locator can find the IDocumentStore and call Initialize on this provider.");
				}
				return _documentStore;
			}
			set { _documentStore = value; }
		}        

		public override void Initialize(string name, NameValueCollection config)
		{
		    if(config == null)
                throw new ArgumentNullException("There are not membership configuration settings.");
            if(string.IsNullOrEmpty(name))
                name = "RavenDBMembershipProvider";
            if(string.IsNullOrEmpty(config["description"]))
                config["description"] = "An Asp.Net membership provider for the RavenDB document database.";

            if (_documentStore == null)
            {                
                string conString = ConfigurationManager.ConnectionStrings[
                    config["connectionStringName"]].ConnectionString;
                
                if (string.IsNullOrEmpty(conString))
                    throw new ProviderException("The connection string name must be set.");
                if (string.IsNullOrEmpty(config["enableEmbeddableDocumentStore"]))
                    throw new ProviderException("RavenDB can run as a service or embedded mode, you must set enableEmbeddableDocumentStore in the web.config.");

                bool embeddedStore = Convert.ToBoolean(config["enableEmbeddableDocumentStore"]);

                if (embeddedStore)
                {
                    _documentStore = new EmbeddableDocumentStore()
                    {
                        ConnectionStringName =
                            config["connectionStringName"]
                    };
                }
                else
                {
                    _documentStore = new DocumentStore()
                    {
                        ConnectionStringName =
                            config["connectionStringName"]
                    };
                }
                _documentStore.Initialize();                
            }

            ApplicationName = string.IsNullOrEmpty(config["applicationName"]) ? System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath : config["applicationName"];

            base.Initialize(name, config);
            
            InitConfigSettings(config);

            //try
            //{
            //    var locator = ServiceLocator.Current;
            //    if (locator != null)
            //    {
            //        DocumentStore = locator.GetInstance<IDocumentStore>();
            //    }
            //}
            //catch (NullReferenceException) // Swallow Nullreference expection that occurs when there is no current service locator.
            //{
            //}
			
		}

        private void InitConfigSettings(NameValueCollection config) {

        }

		public override string ApplicationName { get; set; }

		public override void AddUsersToRoles(string[] usernames, string[] roleNames)
		{
			if (usernames.Length == 0 || roleNames.Length == 0)
			{
				return;
			}
			using (var session = DocumentStore.OpenSession())
			{
				try
				{
                    var users = (from u in session.Query<User>()
                                where u.Username.In(usernames)
                                && u.ApplicationName == ApplicationName 
                                select u).ToList();    
                    
                    var roles = (from r in session.Query<Role>()
                                where r.Name.In(roleNames)
                                && r.ApplicationName == ApplicationName
                                select r.Id).ToList();
					
					foreach (var roleId in roles)
					{
						foreach (var user in users)
						{
							user.Roles.Add(roleId);
						}
					}
					session.SaveChanges();
				}
				catch (Exception ex)
				{
					// TODO: log exception properly
					Console.WriteLine(ex.ToString());
					throw;
				}
			}
		}

		public override void CreateRole(string roleName)
		{
			using (var session = DocumentStore.OpenSession())
			{
				try
				{
					var role = new Role(roleName, null);
					role.ApplicationName = ApplicationName;

					session.Store(role);
					session.SaveChanges();
				}
				catch (Exception ex)
				{
					// TODO: log exception properly
					Console.WriteLine(ex.ToString());
					throw;
				}
			}
		}

		public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
		{
			using (var session = DocumentStore.OpenSession())
			{
				try
				{
					var role = (from r in session.Query<Role>()
							   where r.Name == roleName && r.ApplicationName == ApplicationName
							   select r).SingleOrDefault();
					if (role != null)
					{
						// also find users that have this role
						var users = (from u in session.Query<User>()
									where u.Roles.Any(roleId => roleId == role.Id)
									select u).ToList();
						if (users.Any() && throwOnPopulatedRole)
						{
							throw new Exception(String.Format("Role {0} contains members and cannot be deleted.", role.Name));
						}
						foreach (var user in users)
						{
							user.Roles.Remove(role.Id);
						}
						session.Delete(role);
						session.SaveChanges();
						return true;
					}
					return false;
				}
				catch (Exception ex)
				{
					// TODO: log exception properly
					Console.WriteLine(ex.ToString());
					throw;
				}
			}
		}

		public override string[] FindUsersInRole(string roleName, string usernameToMatch)
		{
			using (var session = DocumentStore.OpenSession())
			{
				// Get role first
				var role = (from r in session.Query<Role>()
							where r.Name == roleName && r.ApplicationName == ApplicationName
							select r).FirstOrDefault();
				if (role != null)
				{
					// Find users
					var users = from u in session.Query<User>()
								where u.Roles.Any(x => x == role.Id) && u.Username == usernameToMatch
								select u.Username;
					return users.ToArray();
				}
				return null;
			}
		}

		public override string[] GetAllRoles()
		{
			using (var session = DocumentStore.OpenSession())
			{
				var roles = (from r in session.Query<Role>()
							where r.ApplicationName == ApplicationName
							select r).ToList();
				return roles.Select(r => r.Name).ToArray();
			}
		}

		public override string[] GetRolesForUser(string username)
		{
			using (var session = DocumentStore.OpenSession())
			{
				var user = (from u in session.Query<User>()
							where u.Username == username && u.ApplicationName == ApplicationName
							select u).SingleOrDefault();
				
                if (user.Roles.Count() != 0)
				{
                    var dbRoles = session.Query<Role>().Where(x => x.Id.In(user.Roles));
					return dbRoles.Select(r => r.Name).ToArray();
				}
				return new string[0];
			}
		}

		public override string[] GetUsersInRole(string roleName)
		{
			using (var session = DocumentStore.OpenSession())
			{
				var role = (from r in session.Query<Role>()
							where r.Name == roleName && r.ApplicationName == ApplicationName
							select r).SingleOrDefault();
				if (role != null)
				{
					var usernames = from u in session.Query<User>()
									where u.Roles.Any( x => x == role.Id)
									select u.Username;
					return usernames.ToArray();
				}
				return null;
			}
		}

		public override bool IsUserInRole(string username, string roleName)
		{
			using (var session = DocumentStore.OpenSession())
			{
				var user = session.Query<User>()
					.Where(u => u.Username == username && u.ApplicationName == ApplicationName)
					.FirstOrDefault();

				if (user != null)
				{
					var role = (from r in session.Query<Role>()
								where r.Name == roleName && r.ApplicationName == ApplicationName
								select r.Id).FirstOrDefault();
					if (role != null)
					{
						return user.Roles.Any(x => x == role);
					}
				}
				return false;
			}
		}

		public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
		{
			if (usernames.Length == 0 || roleNames.Length == 0)
			{
				return;
			}
			using (var session = DocumentStore.OpenSession())
			{
				try
				{
                    var users = (from u in session.Query<User>()
                                 where u.Username.In(usernames) && u.ApplicationName == ApplicationName
                                 select u).ToList();

                    var roles = (from r in session.Query<Role>()
                                 where r.Name.In(roleNames) && r.ApplicationName == ApplicationName
                                 select r.Id).ToList();
                        
                        
					foreach (var roleId in roles)
					{
                        var usersWithRole = users.Where(u => u.Roles.Any(x => x == roleId));
						foreach (var user in usersWithRole)
						{
							user.Roles.Remove(roleId);
						}
					}
					session.SaveChanges();
				}
				catch (Exception ex)
				{
					// TODO: log exception properly
					Console.WriteLine(ex.ToString());
					throw;
				}
			}
		}

		public override bool RoleExists(string roleName)
		{
			using (var session = DocumentStore.OpenSession())
			{
				return session.Query<Role>().Any(r => r.Name == roleName);
			}
		}
	}
}
