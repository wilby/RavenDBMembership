using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Security;
using Raven.Client;
using System.Collections.Specialized;
using System.IO;
using System.Configuration;
using System.Configuration.Provider;
using Raven.Client.Document;
using System.Web.Configuration;
using System.Diagnostics;
using System.Web;
using Raven.Client.Embedded;


namespace RavenDBMembership.Provider
{
    public enum PasswordAttemptTypes
    {
        PasswordAttempt,
        PasswordAnswerAttempt
    }

    public class RavenDBMembershipProvider : MembershipProvider
    {

        #region Private Members

        private const string ProviderName = "RavenDBMembership";
        private static IDocumentStore _documentStore;
        private int _maxInvalidPasswordAttempts;
        private int _passwordAttemptWindow;
        private int _minRequiredNonAlphanumericCharacters;
        private int _minRequiredPasswordLength;
        private string _passwordStrengthRegularExpression;
        private bool _enablePasswordReset;
        private bool _enablePasswordRetrieval;
        private bool _requiresQuestionAndAnswer;
        private bool _requiresUniqueEmail;
        private MembershipPasswordFormat _passwordFormat;
        private string _hashAlgorithm;
        private string _validationKey;

        #endregion

        #region Overriden Public Members

        public override string ApplicationName { get; set; }

        public override bool EnablePasswordReset
        {
            get { return _enablePasswordReset; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return _enablePasswordRetrieval; }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return _maxInvalidPasswordAttempts; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonAlphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return _minRequiredPasswordLength; }
        }

        public override int PasswordAttemptWindow
        {
            get { return _passwordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return _passwordFormat; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _passwordStrengthRegularExpression; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return _requiresQuestionAndAnswer; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return _requiresUniqueEmail; }
        }

        #endregion

		public static IDocumentStore DocumentStore
		{
			get 
			{				
				return _documentStore;
			}
			set { _documentStore = value; }
		}

        
        #region Overriden Public Functions

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("There are no membership configuration settings.");
            if (string.IsNullOrEmpty(name))
                name = "RavenDBMembershipProvider";
            if (string.IsNullOrEmpty(config["description"]))
                config["description"] = "An Asp.Net membership provider for the RavenDB document database.";

            base.Initialize(name, config);

            InitConfigSettings(config);
            InitPasswordEncryptionSettings(config);
            
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
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(args);
            if (args.Cancel)
            {
                throw new MembershipPasswordException("The new password is not valid.");
            }
            using (var session = DocumentStore.OpenSession())
            {
                var user = (from u in session.Query<User>()
                            where u.Username == username && u.ApplicationName == ApplicationName
                            select u).SingleOrDefault();
                //Do not need to track invalid password attempts here because they will be picked up in validateuser
                if (!ValidateUser(username, oldPassword))
                    throw new MembershipPasswordException("Invalid username or old password. "
                    + "You must supply valid credentials to change your password.");

                user.PasswordHash = EncodePassword(newPassword, user.PasswordSalt);
                session.SaveChanges();
            }
            return true;
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password,
            string newPasswordQuestion, string newPasswordAnswer)
        {
            //password attempt tracked in validateuser
            if (!ValidateUser(username, password))
                throw new MembershipPasswordException("You must supply valid credentials to change "
                + "your question and answer.");

            using (var session = DocumentStore.OpenSession())
            {
                User user = (from u in session.Query<User>()
                             where u.Username == username && u.ApplicationName == ApplicationName
                             select u).SingleOrDefault();

                user.PasswordQuestion = newPasswordQuestion;
                user.PasswordAnswer = EncodePassword(newPasswordAnswer, user.PasswordSalt);
                session.SaveChanges();

            }
            return true;
        }

        public override MembershipUser CreateUser(string username, string password, string email,
            string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey,
            out MembershipCreateStatus status)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, password, true);
            OnValidatingPassword(args);
            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            
            //If we require a qeustion and answer for password reset/retrieval and they were not provided throw exception
            if (((_enablePasswordReset || _enablePasswordRetrieval) && _requiresQuestionAndAnswer) && string.IsNullOrEmpty(passwordAnswer))
                throw new ArgumentException("Requires question and answer is set to true and a question and answer were not provided.");


            var user = new User();
            user.Username = username;
            user.PasswordSalt = PasswordUtil.CreateRandomSalt();
            user.PasswordHash = EncodePassword(password, user.PasswordSalt);
            user.Email = email;
            user.ApplicationName = ApplicationName;
            user.DateCreated = DateTime.Now;
            user.PasswordQuestion = passwordQuestion;
            user.PasswordAnswer = string.IsNullOrEmpty(passwordAnswer) ? passwordAnswer : EncodePassword(passwordAnswer, user.PasswordSalt);
            user.IsApproved = isApproved;
            user.IsLockedOut = false;
            user.IsOnline = false;

            using (var session = DocumentStore.OpenSession())
            {
                if (RequiresUniqueEmail)
                {
                    var existingUser = session.Query<User>()
                        .Where(x => x.Email == email && x.ApplicationName == ApplicationName)
                        .FirstOrDefault();

                    if (existingUser != null)
                    {
                        status = MembershipCreateStatus.DuplicateEmail;
                        return null;
                    }
                }


                session.Store(user);
                session.SaveChanges();
                status = MembershipCreateStatus.Success;
                return new MembershipUser(ProviderName, username, user.Id, email, passwordQuestion,
                    user.Comment, isApproved, false, user.DateCreated, new DateTime(1900, 1, 1),
                    new DateTime(1900, 1, 1), DateTime.Now, new DateTime(1900, 1, 1));
            }
        }

        public MembershipUser CreateUser(string username, string password, string email, string fullName,
            string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey,
            out MembershipCreateStatus status)
        {
            MembershipUser user = CreateUser(username, password, email, passwordQuestion, passwordAnswer,
                isApproved, providerUserKey, out status);

            if (user != null)
            {
                using (var session = _documentStore.OpenSession())
                {
                    var ravenUser = session.Load<User>(user.ProviderUserKey.ToString());
                    ravenUser.FullName = fullName;
                    session.SaveChanges();
                }                
            }
            return user;
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            using (var session = DocumentStore.OpenSession())
            {
                try
                {
                    var q = from u in session.Query<User>()
                            where u.Username == username && u.ApplicationName == ApplicationName
                            select u;
                    var user = q.SingleOrDefault();
                    if (user == null)
                    {
                        throw new NullReferenceException("The user could not be deleted, they don't exist.");
                    }
                    session.Delete(user);
                    session.SaveChanges();
                    return true;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry(ApplicationName, ex.ToString());
                    return false;
                }
            }
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex,
            int pageSize, out int totalRecords)
        {
            return FindUsers(u => u.Email.Contains(emailToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex,
            int pageSize, out int totalRecords)
        {
            return FindUsers(u => u.Username.Contains(usernameToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsers(null, pageIndex, pageSize, out totalRecords);
        }

        public override int GetNumberOfUsersOnline()
        {
            using (var session = DocumentStore.OpenSession())
            {
                return (from u in session.Query<User>()
                        where u.ApplicationName == ApplicationName && u.IsOnline == true
                        select u).Count<User>();
            }
        }

        public override string GetPassword(string username, string answer)
        {
            if (!EnablePasswordRetrieval)
                throw new NotSupportedException("Password retrieval feature is not supported.");

            if (PasswordFormat == MembershipPasswordFormat.Hashed)
                throw new NotSupportedException("Password retrieval is not supported with hashed passwords.");

            User user = null;

            using (var session = _documentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.Username == username && u.ApplicationName == ApplicationName
                        select u;
                user = q.SingleOrDefault();


                if (user == null)
                    throw new NullReferenceException("The specified user does not exist.");

                var encodedAnswer = EncodePassword(answer, user.PasswordSalt);
                if (RequiresQuestionAndAnswer && user.PasswordAnswer != encodedAnswer)
                {                    
                    user.FailedPasswordAnswerAttempts++;
                    session.SaveChanges();
                 
                    throw new MembershipPasswordException("The password question's answer is incorrect.");
                }
            }
            if (PasswordFormat == MembershipPasswordFormat.Clear)
                return user.PasswordHash;

            return UnEncodePassword(user.PasswordHash, user.PasswordSalt);
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            var user = GetRavenDbUser(username, userIsOnline);
            if (user != null)
            {
                return UserToMembershipUser(user);
            }
            return null;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Load<User>(providerUserKey.ToString());
                if (user != null)
                {
                    return UserToMembershipUser(user);
                }
                return null;
            }
        }

        public override string GetUserNameByEmail(string email)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.Email == email && u.ApplicationName == ApplicationName
                        select u.Username;
                return q.SingleOrDefault();
            }
        }

        public override string ResetPassword(string username, string answer)
        {
            if (!EnablePasswordReset)
                throw new ProviderException("Password reset is not enabled.");

            using (var session = DocumentStore.OpenSession())
            {
                try
                {
                    var q = from u in session.Query<User>()
                            where u.Username == username && u.ApplicationName == ApplicationName
                            select u;
                    var user = q.SingleOrDefault();
                    if (user == null)
                    {
                        throw new HttpException("The user to reset the password for could not be found.");
                    }
                    if (user.PasswordAnswer != EncodePassword(answer, user.PasswordSalt))
                    {
                        user.FailedPasswordAttempts++;
                        session.SaveChanges();
                        throw new MembershipPasswordException("The password question's answer is incorrect.");
                    }
                    var newPassword = Membership.GeneratePassword(8, 2);
                    user.PasswordHash = EncodePassword(newPassword, user.PasswordSalt);
                    session.SaveChanges();
                    return newPassword;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry(ApplicationName, ex.ToString());
                    throw;
                }
            }
        }

        public override bool UnlockUser(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<User>()
                    .Where(x => x.Username == userName && x.ApplicationName == ApplicationName)
                    .SingleOrDefault();

                if (user == null)
                    return false;

                user.IsLockedOut = false;
                session.SaveChanges();
                return true;
            }
        }

        public override void UpdateUser(MembershipUser user)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.Username == user.UserName && u.ApplicationName == ApplicationName
                        select u;
                var dbUser = q.SingleOrDefault();
                if (dbUser == null)
                {
                    throw new HttpException("The user to update could not be found.");
                }
                dbUser.Username = user.UserName;
                dbUser.Email = user.Email;
                dbUser.DateCreated = user.CreationDate;
                dbUser.DateLastLogin = user.LastLoginDate;                
                dbUser.IsOnline = user.IsOnline;
                dbUser.IsApproved = user.IsApproved;
                dbUser.IsLockedOut = user.IsLockedOut;

                session.SaveChanges();
            }
        }
        
        public override bool ValidateUser(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            using (var session = DocumentStore.OpenSession())
            {
                var user = (from u in session.Query<User>()
                            where u.Username == username && u.ApplicationName == ApplicationName
                            select u).SingleOrDefault();

                if (user == null)
                    return false;

                if (user.PasswordHash == EncodePassword(password, user.PasswordSalt))
                {
                    user.DateLastLogin = DateTime.Now;
                    user.IsOnline = true;
                    user.FailedPasswordAttempts = 0;
                    user.FailedPasswordAnswerAttempts = 0;
                    session.SaveChanges();
                    return true;
                }
                else
                {
                    user.LastFailedPasswordAttempt = DateTime.Now;
                    user.FailedPasswordAttempts++;
                    user.IsLockedOut = IsLockedOutValidationHelper(user);
                    session.SaveChanges();
                }
            }
            return false;
        }

        #endregion

        #region Private Helper Functions

        private bool IsLockedOutValidationHelper(User user)
        {
            long minutesSinceLastAttempt = DateTime.Now.Ticks - user.LastFailedPasswordAttempt.Ticks;
            if (user.FailedPasswordAttempts >= MaxInvalidPasswordAttempts
                && minutesSinceLastAttempt < (long)PasswordAttemptWindow)
                return true;
            return false;
        }

        private User UpdatePasswordAttempts(User u, PasswordAttemptTypes attemptType, bool signedInOk)
        {
            long minutesSinceLastAttempt = DateTime.Now.Ticks - u.LastFailedPasswordAttempt.Ticks;
            if (signedInOk || minutesSinceLastAttempt > (long)PasswordAttemptWindow)
            {
                u.LastFailedPasswordAttempt = new DateTime(1900, 1, 1);
                u.FailedPasswordAttempts = 0;
                u.FailedPasswordAnswerAttempts = 0;
                SaveRavenUser(u);
                return u;
            }
            else
            {
                u.LastFailedPasswordAttempt = DateTime.Now;
                if (attemptType == PasswordAttemptTypes.PasswordAttempt)
                {
                    u.FailedPasswordAttempts++;
                }
                else
                {
                    u.FailedPasswordAnswerAttempts++;
                }
                if (u.FailedPasswordAttempts > MaxInvalidPasswordAttempts
                    || u.FailedPasswordAnswerAttempts > MaxInvalidPasswordAttempts)
                    u.IsLockedOut = true;
            }
            SaveRavenUser(u);
            return u;
        }

        private MembershipUserCollection FindUsers(Func<User, bool> predicate, int pageIndex, int pageSize, out int totalRecords)
        {
            var membershipUsers = new MembershipUserCollection();
            using (var session = DocumentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.ApplicationName == ApplicationName
                        select u;
                IEnumerable<User> results;
                if (predicate != null)
                {
                    results = q.Where(predicate);
                }
                else
                {
                    results = q;
                }
                totalRecords = results.Count();
                var pagedUsers = results.Skip(pageIndex * pageSize).Take(pageSize);
                foreach (var user in pagedUsers)
                {
                    membershipUsers.Add(UserToMembershipUser(user));
                }
            }
            return membershipUsers;
        }

        private MembershipUser UserToMembershipUser(User user)
        {
            return new MembershipUser(ProviderName, user.Username, user.Id, user.Email, user.PasswordQuestion, user.Comment, user.IsApproved, user.IsLockedOut
                , user.DateCreated, user.DateLastLogin.HasValue ? user.DateLastLogin.Value : new DateTime(1900, 1, 1), new DateTime(1900, 1, 1), new DateTime(1900, 1, 1), new DateTime(1900, 1, 1));
        }

        //A helper function for getting a full ravendb User instance.
        private User GetRavenDbUser(string username, bool userIsOnline)
        {
            using (var session = _documentStore.OpenSession())
            {
                var q = from u in session.Query<User>()
                        where u.Username == username && u.ApplicationName == ApplicationName
                        select u;
                var user = q.SingleOrDefault();
                user.IsOnline = userIsOnline;
                session.SaveChanges();
                return user;
            }
        }

        private void SaveRavenUser(User user)
        {
            using (var session = _documentStore.OpenSession())
            {
                session.Store(user);
                session.SaveChanges();
            }
        }

        private void InitConfigSettings(NameValueCollection config)
        {
            ApplicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            _maxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            _passwordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            _minRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredAlphaNumericCharacters"], "1"));
            _minRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            _passwordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], String.Empty));
            _enablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            _enablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "true"));
            _requiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            _requiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));
        }

        private void InitPasswordEncryptionSettings(NameValueCollection config)
        {
            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            MachineKeySection machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            _hashAlgorithm = machineKey.ValidationAlgorithm;
            _validationKey = machineKey.ValidationKey;

            if (machineKey.ValidationKey.Contains("AutoGenerate"))
            {
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                {
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
                }
            }

            string passFormat = config["passwordFormat"];
            if (passFormat == null)
            {
                passFormat = "Hashed";
            }

            switch (passFormat)
            {
                case "Hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                case "Encrypted":
                    _passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Clear":
                    _passwordFormat = MembershipPasswordFormat.Clear;
                    break;
                default:
                    throw new ProviderException("The password format from the custom provider is not supported.");
            }
        }

        /// <summary>
        /// Encode the password //Chris Pels
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private string EncodePassword(string password, string salt)
        {
            string encodedPassword = password;

            switch (_passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    encodedPassword =
                      Convert.ToBase64String(EncryptPassword(Encoding.Unicode.GetBytes(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    if (string.IsNullOrEmpty(salt))
                        throw new ProviderException("A random salt is required with hashed passwords.");
                    encodedPassword = PasswordUtil.HashPassword(password, salt, _hashAlgorithm, _validationKey);
                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }
            return encodedPassword;
        }

        /// <summary>
        /// UnEncode the password //Chris Pels
        /// </summary>
        /// <param name="encodedPassword"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private string UnEncodePassword(string encodedPassword, string salt)
        {
            string password = encodedPassword;

            switch (_passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    password =
                      Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Hashed passwords do not require decoding, just compare hashes.");
                default:
                    throw new ProviderException("Unsupported password format.");
            }
            return password;
        }

        private string GetConfigValue(string value, string defaultValue)
        {
            if (string.IsNullOrEmpty(value))
                return defaultValue;
            return value;
        }

        #endregion

        //#region RavenWrapper
        //private static class RavenWrapper {
        //    private static IDocumentStore _docStore;
        //    private static object syncLock = new object();        

        //    //private constructor forces the use of Initialize
        //    private IDocumentStore Initialize(string connectionStringName, bool embedded)
        //    {
        //        if (_docStore == null)
        //        {
        //            lock (syncLock)
        //            {
        //                if (_docStore == null)
        //                {
        //                    if (embedded)
        //                    {
        //                        _docStore = new EmbeddableDocumentStore()
        //                        {
        //                            ConnectionStringName = connectionStringName
        //                        };
        //                    }
        //                    else
        //                    {
        //                        _docStore = new DocumentStore()
        //                        {
        //                            ConnectionStringName = connectionStringName
        //                        };
        //                    }
        //                    _docStore.Conventions.IdentityPartsSeparator = "-";
        //                    _docStore.Initialize();                        
        //                }
        //            }
        //        }
        //        return _docStore;
        //    }
        //}
        //#endregion
    }
}
