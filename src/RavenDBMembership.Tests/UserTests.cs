using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Data.Linq;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Configuration;
using System.Web.Security;
using System.Xml;
using NUnit.Framework;
using Raven.Client;
using Raven.Client.Client;
using RavenDBMembership.Provider;
using Rhino.Mocks;
using Raven.Client.Document;



namespace RavenDBMembership.Tests
{
    [TestFixture]
	public class UserTests : InMemoryStoreTestcase
    {
        private string _hashAlgorithm;
        private string _validationKey;

        public UserTests()
        {
            System.Configuration.Configuration cfg = 
                WebConfigurationManager.OpenWebConfiguration(
                System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            _hashAlgorithm = machineKey.ValidationAlgorithm;
            _validationKey = machineKey.ValidationKey;
        }

        #region GetValuesFromConfigTests

        [Test]
        public void ApplicationNameTest_should_return_TestApp_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("", CreateConfigFake());

            bool enabled = provider.EnablePasswordReset;

            Assert.IsTrue(enabled);
        }

        [Test]
        public void EnablePasswordResetTest_should_be_true_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            Assert.AreEqual("TestApp", provider.ApplicationName);
        }

        [Test]
        public void EnablePasswordRetrievel_should_return_true_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            bool enabled = provider.EnablePasswordRetrieval;

            Assert.IsTrue(enabled);
        }

        [Test]
        public void MaxInvalidPasswordAttemptsTest_should_return_5_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            int maxPasses = provider.MaxInvalidPasswordAttempts;

            Assert.AreEqual(5, maxPasses);
        }

        [Test]
        public void MinRequiredNonalphanumericCharactersTest_should_return_2_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            int minNonAlpha = provider.MinRequiredNonAlphanumericCharacters;

            Assert.AreEqual(2, minNonAlpha);
        }

        [Test]
        public void MinRequiredPasswordLength_should_return_8_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            int minPassLen = provider.MinRequiredPasswordLength;

            Assert.AreEqual(8, minPassLen);
        }

        [Test]
        public void RequiresQuestionAndAnswerTest_should_return_true_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            bool reqQA = provider.RequiresQuestionAndAnswer;

            Assert.IsTrue(reqQA);
        }

        [Test]
        public void RequiresUniqueEmailTest_should_return_true_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            bool reqEmail = provider.RequiresUniqueEmail;

            Assert.IsTrue(reqEmail);
        }

        [Test]
        public void RequiresUniqueEmail_and_user_exists_CreateUser_returns_null_w_status_of_duplicateEmail()
        {
            using (var store = NewInMemoryStore())
			{
                var config = CreateConfigFake();
                var existingUser = CreateUserFake();
                AddUserToDocumentStore(store, existingUser);

                MembershipCreateStatus status;
                var provider = new RavenDBMembershipProvider();
                provider.Initialize("RavenTest", CreateConfigFake());
                provider.DocumentStore = store;

                var newUser = provider.CreateUser(existingUser.Username, existingUser.PasswordHash,
                    existingUser.Email, existingUser.PasswordQuestion, existingUser.PasswordAnswer,
                    existingUser.IsApproved, null, out status);

                Assert.IsNull(newUser);
                Assert.AreEqual(MembershipCreateStatus.DuplicateEmail, status);
            }
        }

        [Test]
        public void PasswordFormatTest_should_return_encrypted_from_config()
        {
            var provider = new RavenDBMembershipProvider();
            provider.Initialize("RavenTest", CreateConfigFake());

            MembershipPasswordFormat passFormat = provider.PasswordFormat;

            Assert.AreEqual(MembershipPasswordFormat.Encrypted, passFormat);
        }

        #endregion

		[Test]
		public void RunRavenInMemory()
		{
			using (var store = NewInMemoryStore())
			{
				Assert.IsNotNull(store);
			}
		}

		[Test]
		public void StoreUserShouldCreateId()
		{
			var newUser = new User { Username = "martijn", FullName = "Martijn Boland" };
			var newUserIdPrefix = newUser.Id;

			using (var store = NewInMemoryStore())
			{
                AddUserToDocumentStore(store, newUser);
			}

			Assert.AreEqual(newUserIdPrefix + "1", newUser.Id);
		}

		[Test]
		public void CreateNewMembershipUserShouldCreateUserDocument()
		{
			using (var store = NewInMemoryStore())
			{
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;
				MembershipCreateStatus status;
				var membershipUser = provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);
				
                Assert.AreEqual(MembershipCreateStatus.Success, status);
				Assert.IsNotNull(membershipUser);
				Assert.IsNotNull(membershipUser.ProviderUserKey);
				Assert.AreEqual("martijn", membershipUser.UserName);
			}
		}

        [Test]
        public void CreatedUser_should_have_encrypted_password_and_password_answer()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                User fakeU = CreateUserFake();
                var provider = new RavenDBMembershipProvider();                
                provider.Initialize(fakeU.ApplicationName, CreateConfigFake());
                provider.DocumentStore = store;
                var session = store.OpenSession();
                MembershipCreateStatus status;
                
                //Act
                var membershipUser = provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                    fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                    fakeU.IsApproved, null, out status);
                User createdUser = session.Load<User>(membershipUser.ProviderUserKey.ToString());

                //Assert
                //Best I could think to do, not sure its possible to test encrypted strings for actual encryption
                Assert.AreNotEqual(fakeU.PasswordHash, createdUser.PasswordHash);
                Assert.AreNotEqual(fakeU.PasswordAnswer, createdUser.PasswordAnswer);
            }
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void EnableEmbeddableDocumentStore_should_throw_exception_if_not_set()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange                
                var provider = new RavenDBMembershipProvider();
                var config = CreateConfigFake();
                config.Remove("enableEmbeddableDocumentStore");
                
                //Act
                provider.Initialize("TestApp", config);
                
            }
        }

        [Test]        
        public void EnableEmbeddableDocumentStore_should_be_of_type_EmbeddableDocumentStore()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange                
                var provider = new RavenDBMembershipProvider();
                var config = CreateConfigFake();
                config["enableEmbeddableDocumentStore"] = "true";

                //Act
                provider.Initialize("TestApp", config);

                //Asset 
                Assert.IsTrue(provider.DocumentStore.GetType() == typeof(EmbeddableDocumentStore));

            }
        }

        [Test]
        public void EnableEmbeddableDocumentStore_should_be_of_type_DocumentStore()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange                
                var provider = new RavenDBMembershipProvider();
                var config = CreateConfigFake();
                config["enableEmbeddableDocumentStore"] = "false";

                //Act
                provider.Initialize("TestApp", config);

                //Asset 
                Assert.IsTrue(provider.DocumentStore.GetType() == typeof(DocumentStore));

            }
        }

        [Test]
        //In order for this test to pass, you must copy the machine key element from the app.config (actually generate your own) in this test project
        //to the machine.config in the appropriate framework version. This is so that algorithm info grabbed by the 
        //membership provider matches what is in this test. You cannot use AutoGen for the validation and decryption keys.
        public void CreatedUser_should_have_hashed_password_and_password_answer()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                User fakeU = CreateUserFake();
                NameValueCollection nvc = CreateConfigFake();
                nvc["passwordFormat"] = "Hashed";               
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(fakeU.ApplicationName, nvc);
                provider.DocumentStore = store;
                var session = store.OpenSession();
                MembershipCreateStatus status;
                
                //Act
                var membershipUser = provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                    fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                    fakeU.IsApproved, null, out status);
                User createdUser = session.Load<User>(membershipUser.ProviderUserKey.ToString());
                string expected = PasswordUtil.HashPassword(fakeU.PasswordHash, createdUser.PasswordSalt, "HMACSHA256", _validationKey );
                string expectedAnswer = PasswordUtil.HashPassword(fakeU.PasswordAnswer, createdUser.PasswordSalt, "HMACSHA256", _validationKey);
                
                //Assert
                Assert.AreEqual(expected, createdUser.PasswordHash);
                Assert.AreEqual(expectedAnswer, createdUser.PasswordAnswer);               
                
            }
        }

        [Test]        
        public void ValidateUserTest_should_return_false_if_username_is_null_or_empty()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange
                var provider = new RavenDBMembershipProvider();
                provider.DocumentStore = store;

                //Act and Assert
                Assert.IsFalse(provider.ValidateUser("", ""));
                Assert.IsFalse(provider.ValidateUser(null,null));
            }
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void ResetPasswordTest_if_EnablePasswordReset_is_not_enabled_throws_exception()
        {
            //Arrange
            var config = CreateConfigFake();
            config["enablePasswordReset"] = "false";
            var provider = new RavenDBMembershipProvider();
            provider.Initialize(config["applicationName"], config);

            //Act and Assert
            provider.ResetPassword(null, null);
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void ResetPasswordTest_invalid_passwordanswerattempt_increments_failedPasswordAttempts(){
            using (var store = NewInMemoryStore())
            {
                //Arrange
                var config = CreateConfigFake();
                var fakeU = CreateUserFake();
                config["enablePasswordReset"] = "false";
                MembershipCreateStatus status;
                var provider = new RavenDBMembershipProvider();
                provider.DocumentStore = store;
                provider.Initialize(config["applicationName"], config);
                var membershipUser = provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                        fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                        fakeU.IsApproved, null, out status);

                //Act 
                provider.ResetPassword(membershipUser.UserName, "WrongPasswordAnswerAnswer");
                using (var session = provider.DocumentStore.OpenSession())
                {
                    var user = session.Load<User>(membershipUser.ProviderUserKey.ToString());
                    //Assert
                    Assert.IsTrue(user.FailedPasswordAnswerAttempts > 0);
                }
            }
        }

		[Test]
		public void ChangePassword()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;
				MembershipCreateStatus status;
				var membershipUser = provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);

				// Act
				provider.ChangePassword("martijn", "1234ABCD", "DCBA4321");
				 

				// Assert
				Assert.True(provider.ValidateUser("martijn", "DCBA4321"));
			}
		}

        [Test]
        public void ChangePasswordQuestionAndAnwerTest_should_change_question_and_answer()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange                
                MembershipCreateStatus status;
                User fakeUser = CreateUserFake();
                string newQuestion = "MY NAME", newAnswer = "WILBY";
                
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(fakeUser.ApplicationName, CreateConfigFake());
                provider.DocumentStore = store;

                var membershipUser = provider.CreateUser(fakeUser.Username, fakeUser.PasswordHash, fakeUser.Email, fakeUser.PasswordQuestion,
                    fakeUser.PasswordAnswer, fakeUser.IsApproved, null, out status);

                // Act
                provider.ChangePasswordQuestionAndAnswer("wilby", "1234ABCD", newQuestion, newAnswer);


                using (var session = store.OpenSession())
                {
                    var user = session.Load<User>(membershipUser.ProviderUserKey.ToString());
                    Assert.AreEqual(newQuestion, user.PasswordQuestion);
                }
                
            }
        }

		[Test]
		public void DeleteUser()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;
				MembershipCreateStatus status;
				var membershipUser = provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);                

				// Act
				provider.DeleteUser("martijn", true);

				// Assert
                Thread.Sleep(500);
				using (var session = store.OpenSession())
				{
					Assert.AreEqual(0, session.Query<User>().Count());
				}
			}
		}

        [Test]
        public void GetNumberOfUsersOnlineTest_should_return_4_user()
        {
            using (var store = NewInMemoryStore())
            {
                using (var session = store.OpenSession())
                {
                    // Arrange                    
                    for (int i = 0; i < 5; i++)
                    {
                        var u = CreateUserFake();
                        if (i == 4)
                            u.IsOnline = false;
                        u.Username = u.Username + i;
                        session.Store(u);                        
                    }                    
                    session.SaveChanges();                    
                    var provider = new RavenDBMembershipProvider();
                    var config = CreateConfigFake();                    
                    provider.DocumentStore = store;
                    provider.Initialize(config["applicationName"], config);

                    // Act                     
                    int totalOnline = provider.GetNumberOfUsersOnline();                    

                    // Assert
                    Assert.AreEqual(4, totalOnline);                    
                }
            }
        }

		[Test]
		public void GetAllUsersShouldReturnAllUsers()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				CreateUsersInDocumentStore(store, 5);
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;
				
				// Act
				 
				int totalRecords;
				var membershipUsers = provider.GetAllUsers(0, 10, out totalRecords);

				// Assert
				Assert.AreEqual(5, totalRecords);				
				Assert.AreEqual(5, membershipUsers.Count);				
			}
		}

		[Test]
		public void FindUsersByUsernamePart()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				CreateUsersInDocumentStore(store, 5);
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;

				// Act
				 
				int totalRecords;
				var membershipUsers = provider.FindUsersByName("ser", 0, 10, out totalRecords); // Usernames are User1 .. Usern

				// Assert
				Assert.AreEqual(5, totalRecords); // All users should be returned
				Assert.AreEqual(5, membershipUsers.Count);
			}
		}

		[Test]
		public void FindUsersWithPaging()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				CreateUsersInDocumentStore(store, 10);
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;

				// Act
				 
				int totalRecords;
				var membershipUsers = provider.GetAllUsers(0, 5, out totalRecords);

				// Assert
				Assert.AreEqual(10, totalRecords); // All users should be returned
				Assert.AreEqual(5, membershipUsers.Count);
			}
		}

		[Test]
		public void FindUsersForDomain()
		{
			using (var store = NewInMemoryStore())
			{
				// Arrange
				CreateUsersInDocumentStore(store, 10);
				var provider = new RavenDBMembershipProvider();
				provider.DocumentStore = store;
                
				// Act
				 
				int totalRecords;
				var membershipUsers = provider.FindUsersByEmail("@foo.bar", 0, 2, out totalRecords);
				int totalRecordsForUnknownDomain;
				var membershipUsersForUnknownDomain = provider.FindUsersByEmail("@foo.baz", 0, 2, out totalRecordsForUnknownDomain);

				// Assert
				Assert.AreEqual(10, totalRecords); // All users should be returned
				Assert.AreEqual(2, membershipUsers.Count);
				Assert.AreEqual(0, totalRecordsForUnknownDomain);
				Assert.AreEqual(0, membershipUsersForUnknownDomain.Count);
			}
		}

        [Test]
        [ExpectedException("System.NotSupportedException")]
        public void GetPasswordTest_throws_exception_if_EnablePasswordRetrieval_is_false()
        {
            using (var store = NewInMemoryStore())
			{   
                // Arrange                
			    var user = CreateUserFake();
                var config = CreateConfigFake();
                config["enablePasswordRetrieval"] = "false";
			    var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
			    provider.DocumentStore = store;
			    
                // Act and Assert
			    string password = provider.GetPassword(user.Username, user.PasswordAnswer);
            }
        }

        [Test]
        [ExpectedException("System.NotSupportedException")]
        public void GetPasswordTest_throws_exception_if_enablePasswordRetrieval_and_password_is_hashed()
        {
            using (var store = NewInMemoryStore())
			{   
                // Arrange                
			    var user = CreateUserFake();
                var config = CreateConfigFake();
                config["passwordFormat"] = "Hashed";
			    var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
			    provider.DocumentStore = store;

                // Act and Assert				
			    string password = provider.GetPassword(user.Username, user.PasswordAnswer);
            }
        }

        [Test]
        [ExpectedException("System.NullReferenceException")]
        public void GetPasswordTest_throws_exception_user_does_not_exist()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange                                
                var config = CreateConfigFake();                
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;

                // Act and Assert				
                string password = provider.GetPassword("NOUSER", "NOANSWER");
            }
        }

        [Test]
        [ExpectedException("System.Web.Security.MembershipPasswordException")]
        public void GetPasswordTest_throws_exception_if_password_answer_is_wrong()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange                                                
                var config = CreateConfigFake();
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;
                var user = CreateUserFake();
                MembershipCreateStatus status;
                provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                    user.IsApproved, null, out status);


                // Act and Assert				
                string password = provider.GetPassword(user.Username, "NOANSWER");
            }
        }

        [Test]        
        public void GetPasswordTest_returns_plain_text_password()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange                                                
                var config = CreateConfigFake();
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;
                var user = CreateUserFake();
                MembershipCreateStatus status;
                provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                    user.IsApproved, null, out status);
                
                // Act
                string password = provider.GetPassword(user.Username, user.PasswordAnswer);

                //Assert
                Assert.AreEqual(user.PasswordHash, password);
            }
        }

        [Test]
        public void GetPasswordTest_FailedPasswordAnswerAttempts_are_incremented_on_failed_attempt()
        {
            using (var store = NewInMemoryStore())
            {
                // Arrange                                                
                var config = CreateConfigFake();
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;
                var user = CreateUserFake();
                MembershipCreateStatus status;
                MembershipUser memUser = provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                    user.IsApproved, null, out status);
                              

                User updatedUser = null;                
                try
                {
                    // Act
                    string password = provider.GetPassword(user.Username, "WrongPasswordAnswerAnswer");
                } catch(MembershipPasswordException) {
                
                }
                using (var session = provider.DocumentStore.OpenSession())
                {
                    updatedUser = session.Query<User>().Where(x => x.Id == memUser.ProviderUserKey)
                        .SingleOrDefault();
                }

                //Assert
                Assert.IsTrue(updatedUser.FailedPasswordAnswerAttempts > 0);
            }
        }

        [Test]
        public void UnlockUserTest_user_is_actually_unlocked_and_returns_true()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                var config = CreateConfigFake();                
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;

                User wilby = null;

                using (var session = provider.DocumentStore.OpenSession())
                {
                    wilby = CreateUserFake();
                    wilby.IsLockedOut = true;

                    session.Store(wilby);
                    session.SaveChanges();
                }

                //Act
                bool results = provider.UnlockUser(wilby.Username);
                var updatedUser = GetUserFromDocumentStore(provider.DocumentStore, wilby.Username);
                
                //Assert 
                Assert.IsTrue(results);
                Assert.IsFalse(updatedUser.IsLockedOut);
            }
        }

        [Test]
        public void UnlockUserTest_user_is_not_unlocked_returns_false()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                var config = CreateConfigFake();                
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;

                //Act
                bool results = provider.UnlockUser("NOUSER");

                //Assert 
                Assert.IsFalse(results);
            }
        }

        [Test]
        public void IsLockedOut_test_true_when_failedPasswordAttempts_is_gt_maxPasswordAttempts()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                var config = CreateConfigFake();
                var user = CreateUserFake();
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;

                //Act
                using (var session = provider.DocumentStore.OpenSession())
                {
                    session.Store(user);
                    session.SaveChanges();
                }
                for (int i = 0; i < 10; i++)
                {
                    provider.ValidateUser("wilby", "wrongpassword");
                }
                using (var session = provider.DocumentStore.OpenSession())
                {
                    user = session.Query<User>().Where(x => x.Username == user.Username && x.ApplicationName == user.ApplicationName).SingleOrDefault();
                }

                //Assert 
                Assert.IsTrue(user.IsLockedOut);
            }
        }

        [Test]
        public void IsLockedOut_test_false_when_failedPasswordAttempts_is_gt_maxPasswordAttempts_and_passwordWindow_is_already_past()
        {
            using (var store = NewInMemoryStore())
            {
                //Arrange
                var config = CreateConfigFake();
                config["passwordAttemptWindow"] = "0";
                var user = CreateUserFake();
                var provider = new RavenDBMembershipProvider();
                provider.Initialize(config["applicationName"], config);
                provider.DocumentStore = store;

                //Act
                using (var session = provider.DocumentStore.OpenSession())
                {
                    session.Store(user);
                    session.SaveChanges();
                }
                for (int i = 0; i < 10; i++)
                {
                    provider.ValidateUser("wilby", "wrongpassword");
                }
                using (var session = provider.DocumentStore.OpenSession())
                {
                    user = session.Query<User>().Where(x => x.Username == user.Username && x.ApplicationName == user.ApplicationName).SingleOrDefault();
                }

                //Assert 
                Assert.IsFalse(user.IsLockedOut);
            }
        }

        private User GetUserFromDocumentStore(IDocumentStore store, string username)
        {
            using (var session = store.OpenSession())
            {
                return session.Query<User>().Where(x => x.Username == username).FirstOrDefault();                
            }
        }

        private void AddUserToDocumentStore(IDocumentStore store, User user)
        {
            using (var session = store.OpenSession())
            {
                session.Store(user);
                session.SaveChanges();
            }
        }

        private void CreateUsersInDocumentStore(IDocumentStore store, int numberOfUsers)
		{
			var users = CreateDummyUsers(numberOfUsers);
			using (var session = store.OpenSession())
			{
				foreach (var user in users)
				{
					session.Store(user);
				}
				session.SaveChanges();
			}
		}

		private IList<User> CreateDummyUsers(int numberOfUsers)
		{
			var users = new List<User>(numberOfUsers);
			for (int i = 0; i < numberOfUsers; i++)
			{
				users.Add(new User { Username = String.Format("User{0}", i), Email = String.Format("User{0}@foo.bar", i) });
			}
			return users;
		}

        private static NameValueCollection CreateConfigFake() { 
            NameValueCollection config = new NameValueCollection(); 
            config.Add("applicationName", "TestApp"); 
            config.Add("enablePasswordReset", "true"); 
            config.Add("enablePasswordRetrieval", "true"); 
            config.Add("maxInvalidPasswordAttempts", "5");
            config.Add("minRequiredAlphaNumericCharacters", "2"); 
            config.Add("minRequiredPasswordLength", "8"); 
            config.Add("requiresQuestionAndAnswer", "true"); 
            config.Add("requiresUniqueEmail", "true"); 
            config.Add("passwordAttemptWindow", "10");
            config.Add("passwordFormat", "Encrypted");
            config.Add("connectionStringName", "Server");
            config.Add("enableEmbeddableDocumentStore", "true");
            return config; 
        }

        private User CreateUserFake()
        {
            return new User()
            {
                Username = "wilby",
                PasswordHash = "1234ABCD",
                PasswordSalt = PasswordUtil.CreateRandomSalt(),
                Email = "wilby@wcjj.net",
                PasswordQuestion = "A QUESTION",
                PasswordAnswer = "A ANSWER",                
                IsOnline = true,
                IsApproved = true,
                Comment = "A FAKE USER",
                ApplicationName = "TestApp",
                DateCreated = DateTime.Now,
                DateLastLogin = DateTime.Now,
                FailedPasswordAttempts = 0,
                FullName = "Wilby Jackson",
                IsLockedOut = false
            };
        }
	}
}

