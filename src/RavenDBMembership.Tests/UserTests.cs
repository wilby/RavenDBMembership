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
using RavenDBMembership.Provider;
using Rhino.Mocks;
using Raven.Client.Document;
using Raven.Client.Embedded;



namespace RavenDBMembership.Tests
{
    [TestFixture]
	public class UserTests : InMemoryStoreTestcase
    {
        private string _hashAlgorithm;
        private string _validationKey;
        private RavenDBMembershipProvider _provider;

        public UserTests()
        {
            System.Configuration.Configuration cfg = 
                WebConfigurationManager.OpenWebConfiguration(
                System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            _hashAlgorithm = machineKey.ValidationAlgorithm;
            _validationKey = machineKey.ValidationKey;
        }

        [SetUp]
        public void Setup()
        {
            _provider = new RavenDBMembershipProvider();
            RavenDBMembershipProvider.DocumentStore = null;
            RavenDBMembershipProvider.DocumentStore = NewInMemoryStore();
                       
        }

        [TearDown]
        public void TearDown()
        {
            if (RavenDBMembershipProvider.DocumentStore != null)
                RavenDBMembershipProvider.DocumentStore.Dispose();
        }

        #region GetValuesFromConfigTests

        [Test]
        public void ApplicationNameTest_should_return_TestApp_from_config()
        {
            
            _provider.Initialize("", CreateConfigFake());

            bool enabled = _provider.EnablePasswordReset;

            Assert.IsTrue(enabled);
        }

        [Test]
        public void EnablePasswordResetTest_should_be_true_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            Assert.AreEqual("TestApp", _provider.ApplicationName);
        }

        [Test]
        public void EnablePasswordRetrievel_should_return_true_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            bool enabled = _provider.EnablePasswordRetrieval;

            Assert.IsTrue(enabled);
        }

        [Test]
        public void MaxInvalidPasswordAttemptsTest_should_return_5_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            int maxPasses = _provider.MaxInvalidPasswordAttempts;

            Assert.AreEqual(5, maxPasses);
        }

        [Test]
        public void MinRequiredNonalphanumericCharactersTest_should_return_2_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            int minNonAlpha = _provider.MinRequiredNonAlphanumericCharacters;

            Assert.AreEqual(2, minNonAlpha);
        }

        [Test]
        public void MinRequiredPasswordLength_should_return_8_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            int minPassLen = _provider.MinRequiredPasswordLength;

            Assert.AreEqual(8, minPassLen);
        }

        [Test]
        public void RequiresQuestionAndAnswerTest_should_return_true_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            bool reqQA = _provider.RequiresQuestionAndAnswer;

            Assert.IsTrue(reqQA);
        }

        [Test]
        public void RequiresUniqueEmailTest_should_return_true_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            bool reqEmail = _provider.RequiresUniqueEmail;

            Assert.IsTrue(reqEmail);
        }

        [Test]
        public void RequiresUniqueEmail_and_user_exists_CreateUser_returns_null_w_status_of_duplicateEmail()
        {
            //Arrange
            var config = CreateConfigFake();
            var existingUser = CreateUserFake();
            AddUserToDocumentStore(RavenDBMembershipProvider.DocumentStore, existingUser);
            MembershipCreateStatus status;
            _provider.Initialize("RavenTest", CreateConfigFake());

            //Act
            var newUser = _provider.CreateUser(existingUser.Username, existingUser.PasswordHash,
                existingUser.Email, existingUser.PasswordQuestion, existingUser.PasswordAnswer,
                existingUser.IsApproved, null, out status);

            //Assert
            Assert.IsNull(newUser);
            Assert.AreEqual(MembershipCreateStatus.DuplicateEmail, status);
        }

        [Test]
        public void PasswordFormatTest_should_return_encrypted_from_config()
        {
            
            _provider.Initialize("RavenTest", CreateConfigFake());

            MembershipPasswordFormat passFormat = _provider.PasswordFormat;

            Assert.AreEqual(MembershipPasswordFormat.Encrypted, passFormat);
        }

        #endregion

		[Test]
		public void StoreUserShouldCreateId()
		{
			var newUser = new User { Username = "martijn", FullName = "Martijn Boland" };
			var newUserIdPrefix = newUser.Id;

            AddUserToDocumentStore(RavenDBMembershipProvider.DocumentStore, newUser);
			
			Assert.AreEqual(newUserIdPrefix + "1", newUser.Id);
		}

		[Test]
		public void CreateNewMembershipUserShouldCreateUserDocument()
		{			
			MembershipCreateStatus status;
			var membershipUser = _provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);
				
            Assert.AreEqual(MembershipCreateStatus.Success, status);
			Assert.IsNotNull(membershipUser);
			Assert.IsNotNull(membershipUser.ProviderUserKey);
			Assert.AreEqual("martijn", membershipUser.UserName);
		
		}

        [Test]
        public void CreatedUser_should_have_encrypted_password_and_password_answer()
        {
            //Arrange
            User fakeU = CreateUserFake();                               
            _provider.Initialize(fakeU.ApplicationName, CreateConfigFake());
                
            var session = RavenDBMembershipProvider.DocumentStore.OpenSession();
            MembershipCreateStatus status;
                
            //Act
            var membershipUser = _provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                fakeU.IsApproved, null, out status);
            User createdUser = session.Load<User>(membershipUser.ProviderUserKey.ToString());

            //Assert
            //Best I could think to do, not sure its possible to test encrypted strings for actual encryption
            Assert.AreNotEqual(fakeU.PasswordHash, createdUser.PasswordHash);
            Assert.AreNotEqual(fakeU.PasswordAnswer, createdUser.PasswordAnswer);
         
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void EnableEmbeddableDocumentStore_should_throw_exception_if_not_set()
        {
            //Arrange                                       
            var config = CreateConfigFake();
            config.Remove("enableEmbeddableDocumentStore");
            RavenDBMembershipProvider.DocumentStore = null;

            //Act
            _provider.Initialize("TestApp", config);            
        }

        [Test]        
        public void EnableEmbeddableDocumentStore_should_be_of_type_EmbeddableDocumentStore()
        {
            //Arrange                            
            var config = CreateConfigFake();
            config["enableEmbeddableDocumentStore"] = "true";
            RavenDBMembershipProvider.DocumentStore = null;


            //Act
            _provider.Initialize("TestApp", config);

            //Asset 
            Assert.IsTrue(RavenDBMembershipProvider.DocumentStore.GetType() == typeof(EmbeddableDocumentStore));

        }

        [Test]
        public void EnableEmbeddableDocumentStore_should_be_of_type_DocumentStore()
        {   
            //Arrange                            
            var config = CreateConfigFake();
            config["enableEmbeddableDocumentStore"] = "false";
            RavenDBMembershipProvider.DocumentStore = null;
            //Act
            _provider.Initialize("TestApp", config);

            //Asset 
            Assert.IsTrue(RavenDBMembershipProvider.DocumentStore.GetType() == typeof(DocumentStore));
        }

        [Test(Description=@"In order for this test to pass, you must copy the machine key element from the app.config in this test project
        to the machine.config in the appropriate framework version. This is so that algorithm info grabbed by the 
        membership provider matches what is in this test. You cannot use AutoGen for the validation and decryption keys.")]
        public void CreatedUser_should_have_hashed_password_and_password_answer()
        {            
            //Arrange
            User fakeU = CreateUserFake();
            NameValueCollection nvc = CreateConfigFake();
            nvc["passwordFormat"] = "Hashed";               
                
            _provider.Initialize(fakeU.ApplicationName, nvc);            
            MembershipCreateStatus status;
                
            //Act
            var membershipUser = _provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                fakeU.IsApproved, null, out status);
            User createdUser;
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                createdUser = session.Load<User>(membershipUser.ProviderUserKey.ToString());
            }
            string expected = PasswordUtil.HashPassword(fakeU.PasswordHash, createdUser.PasswordSalt, "HMACSHA256", _validationKey );
            string expectedAnswer = PasswordUtil.HashPassword(fakeU.PasswordAnswer, createdUser.PasswordSalt, "HMACSHA256", _validationKey);
                
            //Assert
            
            Assert.AreEqual(expected, createdUser.PasswordHash);
            Assert.AreEqual(expectedAnswer, createdUser.PasswordAnswer);               
             
        }

        [Test]        
        public void ValidateUserTest_should_return_false_if_username_is_null_or_empty()
        {
            //Act and Assert
            Assert.IsFalse(_provider.ValidateUser("", ""));
            Assert.IsFalse(_provider.ValidateUser(null, null));
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void ResetPasswordTest_if_EnablePasswordReset_is_not_enabled_throws_exception()
        {
            //Arrange
            var config = CreateConfigFake();
            config["enablePasswordReset"] = "false";
            
            _provider.Initialize(config["applicationName"], config);

            //Act and Assert
            _provider.ResetPassword(null, null);
        }

        [Test]
        [ExpectedException("System.Configuration.Provider.ProviderException")]
        public void ResetPasswordTest_invalid_passwordanswerattempt_increments_failedPasswordAttempts(){
            //Arrange
            var config = CreateConfigFake();
            var fakeU = CreateUserFake();
            config["enablePasswordReset"] = "false";
            MembershipCreateStatus status;
                
            _provider.Initialize(config["applicationName"], config);
            var membershipUser = _provider.CreateUser(fakeU.Username, fakeU.PasswordHash,
                    fakeU.Email, fakeU.PasswordQuestion, fakeU.PasswordAnswer,
                    fakeU.IsApproved, null, out status);

            //Act 
            _provider.ResetPassword(membershipUser.UserName, "WrongPasswordAnswerAnswer");
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                var user = session.Load<User>(membershipUser.ProviderUserKey.ToString());
                //Assert
                Assert.IsTrue(user.FailedPasswordAnswerAttempts > 0);
            }
        }

		[Test]
		public void ChangePassword()
		{	
			// Arrange
			MembershipCreateStatus status;
			var membershipUser = _provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);

			// Act
			_provider.ChangePassword("martijn", "1234ABCD", "DCBA4321");
            var o = -1;
            var user = _provider.FindUsersByName("martijn", 0, 0 , out o);

			// Assert
			Assert.True(_provider.ValidateUser("martijn", "DCBA4321"));			
		}

        [Test]
        public void ChangePasswordQuestionAndAnwerTest_should_change_question_and_answer()
        {
            // Arrange                
            MembershipCreateStatus status;
            User fakeUser = CreateUserFake();
            string newQuestion = "MY NAME", newAnswer = "WILBY";
                
                
            _provider.Initialize(fakeUser.ApplicationName, CreateConfigFake());            

            var membershipUser = _provider.CreateUser(fakeUser.Username, fakeUser.PasswordHash, fakeUser.Email, fakeUser.PasswordQuestion,
                fakeUser.PasswordAnswer, fakeUser.IsApproved, null, out status);

            // Act
            _provider.ChangePasswordQuestionAndAnswer("wilby", "1234ABCD", newQuestion, newAnswer);


            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                var user = session.Load<User>(membershipUser.ProviderUserKey.ToString());
                Assert.AreEqual(newQuestion, user.PasswordQuestion);
            }
        }

		[Test]
		public void DeleteUser()
		{
			
			{
				// Arrange
				MembershipCreateStatus status;
				var membershipUser = _provider.CreateUser("martijn", "1234ABCD", "martijn@boland.org", null, null, true, null, out status);                

				// Act
				_provider.DeleteUser("martijn", true);

				// Assert
                Thread.Sleep(500);
				using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
				{
					Assert.AreEqual(0, session.Query<User>().Count());
				}
			}
		}

        [Test]
        public void GetNumberOfUsersOnlineTest_should_return_4_user()
        {
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
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
                    
                var config = CreateConfigFake();                    
                _provider.Initialize(config["applicationName"], config);

                // Act                     
                int totalOnline = _provider.GetNumberOfUsersOnline();                    

                // Assert
                Assert.AreEqual(4, totalOnline);                    
            }
        }

		[Test]
		public void GetAllUsersShouldReturnAllUsers()
		{	
			// Arrange
			CreateUsersInDocumentStore(RavenDBMembershipProvider.DocumentStore, 5);

			// Act
			int totalRecords;
			var membershipUsers = _provider.GetAllUsers(0, 10, out totalRecords);

			// Assert
			Assert.AreEqual(5, totalRecords);				
			Assert.AreEqual(5, membershipUsers.Count);		
		}

		[Test]
		public void FindUsersByUsernamePart()
		{
			// Arrange
			CreateUsersInDocumentStore(RavenDBMembershipProvider.DocumentStore, 5);			

			// Act 
			int totalRecords;
			var membershipUsers = _provider.FindUsersByName("ser", 0, 10, out totalRecords); // Usernames are User1 .. Usern

			// Assert
			Assert.AreEqual(5, totalRecords); // All users should be returned
			Assert.AreEqual(5, membershipUsers.Count);
		}

		[Test]
		public void FindUsersWithPaging()
		{
			// Arrange
            CreateUsersInDocumentStore(RavenDBMembershipProvider.DocumentStore, 10);

			// Act 
			int totalRecords;
			var membershipUsers = _provider.GetAllUsers(0, 5, out totalRecords);

			// Assert
			Assert.AreEqual(10, totalRecords); // All users should be returned
			Assert.AreEqual(5, membershipUsers.Count);
			
		}

        [Test]
        public void FindUsersForDomain()
        {
            // Arrange
            CreateUsersInDocumentStore(RavenDBMembershipProvider.DocumentStore, 10);

            // Act
            int totalRecords;
            var membershipUsers = _provider.FindUsersByEmail("@foo.bar", 0, 2, out totalRecords);
            int totalRecordsForUnknownDomain;
            var membershipUsersForUnknownDomain = _provider.FindUsersByEmail("@foo.baz", 0, 2, out totalRecordsForUnknownDomain);

            // Assert
            Assert.AreEqual(10, totalRecords); // All users should be returned
            Assert.AreEqual(2, membershipUsers.Count);
            Assert.AreEqual(0, totalRecordsForUnknownDomain);
            Assert.AreEqual(0, membershipUsersForUnknownDomain.Count);
            
        }

        [Test]
        [ExpectedException("System.NotSupportedException")]
        public void GetPasswordTest_throws_exception_if_EnablePasswordRetrieval_is_false()
        {
            // Arrange                
            var user = CreateUserFake();
            var config = CreateConfigFake();
            config["enablePasswordRetrieval"] = "false";

            _provider.Initialize(config["applicationName"], config);

            // Act and Assert
            string password = _provider.GetPassword(user.Username, user.PasswordAnswer);
        }

        [Test]
        [ExpectedException("System.NotSupportedException")]
        public void GetPasswordTest_throws_exception_if_enablePasswordRetrieval_and_password_is_hashed()
        {
            // Arrange                
            var user = CreateUserFake();
            var config = CreateConfigFake();
            config["passwordFormat"] = "Hashed";
            _provider.Initialize(config["applicationName"], config);

            // Act and Assert				
            string password = _provider.GetPassword(user.Username, user.PasswordAnswer);
        }

        [Test]
        [ExpectedException("System.NullReferenceException")]
        public void GetPasswordTest_throws_exception_user_does_not_exist()
        {
            // Arrange                                
            var config = CreateConfigFake();
            _provider.Initialize(config["applicationName"], config);
            
            // Act and Assert				
            string password = _provider.GetPassword("NOUSER", "NOANSWER");
        }

        [Test]
        [ExpectedException("System.Web.Security.MembershipPasswordException")]
        public void GetPasswordTest_throws_exception_if_password_answer_is_wrong()
        {
            // Arrange                                                
            var config = CreateConfigFake();
            _provider.Initialize(config["applicationName"], config);            
            var user = CreateUserFake();
            MembershipCreateStatus status;
            _provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                user.IsApproved, null, out status);


            // Act and Assert				
            string password = _provider.GetPassword(user.Username, "NOANSWER");
        }

        [Test]
        public void GetPasswordTest_returns_plain_text_password()
        {
            // Arrange                                                
            var config = CreateConfigFake();
            _provider.Initialize(config["applicationName"], config);                
            var user = CreateUserFake();
            MembershipCreateStatus status;
            _provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                user.IsApproved, null, out status);

            // Act
            string password = _provider.GetPassword(user.Username, user.PasswordAnswer);

            //Assert
            Assert.AreEqual(user.PasswordHash, password);
        }

        [Test]
        public void GetPasswordTest_FailedPasswordAnswerAttempts_are_incremented_on_failed_attempt()
        {
            // Arrange                                                
            var config = CreateConfigFake();

            _provider.Initialize(config["applicationName"], config);                
            var user = CreateUserFake();
            MembershipCreateStatus status;
            MembershipUser memUser = _provider.CreateUser(user.Username, user.PasswordHash, user.Email, user.PasswordQuestion, user.PasswordAnswer,
                user.IsApproved, null, out status);


            User updatedUser = null;
            try
            {
                // Act
                string password = _provider.GetPassword(user.Username, "WrongPasswordAnswerAnswer");
            }
            catch (MembershipPasswordException)
            {

            }
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                updatedUser = session.Load<User>(new string[] { memUser.ProviderUserKey.ToString() }).FirstOrDefault();
                    
            }

            //Assert
            Assert.IsTrue(updatedUser.FailedPasswordAnswerAttempts > 0);            
        }

        [Test]
        public void UnlockUserTest_user_is_actually_unlocked_and_returns_true()
        {
            //Arrange
            var config = CreateConfigFake();
            _provider.Initialize(config["applicationName"], config);
            User wilby = null;
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                wilby = CreateUserFake();
                wilby.IsLockedOut = true;

                session.Store(wilby);
                session.SaveChanges();
            }

            //Act
            bool results = _provider.UnlockUser(wilby.Username);
            var updatedUser = GetUserFromDocumentStore(RavenDBMembershipProvider.DocumentStore, wilby.Username);

            //Assert 
            Assert.IsTrue(results);
            Assert.IsFalse(updatedUser.IsLockedOut);
        }

        [Test]
        public void UnlockUserTest_user_is_not_unlocked_returns_false()
        {
            //Arrange
            var config = CreateConfigFake();

            _provider.Initialize(config["applicationName"], config);
            //Act
            bool results = _provider.UnlockUser("NOUSER");

            //Assert 
            Assert.IsFalse(results);
            
        }

        [Test]
        public void IsLockedOut_test_true_when_failedPasswordAttempts_is_gt_maxPasswordAttempts()
        {
            //Arrange
            var config = CreateConfigFake();
            var user = CreateUserFake();
            _provider.Initialize(config["applicationName"], config);
            
            //Act
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                session.Store(user);
                session.SaveChanges();
            }
            for (int i = 0; i < 10; i++)
            {
                _provider.ValidateUser("wilby", "wrongpassword");
            }
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                user = session.Query<User>().Where(x => x.Username == user.Username && x.ApplicationName == user.ApplicationName).SingleOrDefault();
            }

            //Assert 
            Assert.IsTrue(user.IsLockedOut);
        }

        [Test]
        public void IsLockedOut_test_false_when_failedPasswordAttempts_is_gt_maxPasswordAttempts_and_passwordWindow_is_already_past()
        {
            //Arrange
            var config = CreateConfigFake();
            config["passwordAttemptWindow"] = "0";
            var user = CreateUserFake();
            _provider.Initialize(config["applicationName"], config);            

            //Act
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                session.Store(user);
                session.SaveChanges();
            }
            for (int i = 0; i < 10; i++)
            {
                _provider.ValidateUser("wilby", "wrongpassword");
            }
            using (var session = RavenDBMembershipProvider.DocumentStore.OpenSession())
            {
                user = session.Query<User>().Where(x => x.Username == user.Username && x.ApplicationName == user.ApplicationName).SingleOrDefault();
            }

            //Assert 
            Assert.IsFalse(user.IsLockedOut);
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

