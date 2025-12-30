const admin = require('firebase-admin');
const serviceAccount = require('./serviceAcoountKey.json');

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: serviceAccount.project_id
});

const auth = admin.auth();

async function createAdminUser() {
  const email = 'admin@gmail.com';
  const password = 'Admin123!';
  
  try {
    // Check if user already exists
    let user;
    try {
      user = await auth.getUserByEmail(email);
      console.log(`✅ User ${email} already exists with UID: ${user.uid}`);
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        // Create the user
        user = await auth.createUser({
          email: email,
          password: password,
          emailVerified: true,
          displayName: 'Admin User'
        });
        console.log(`✅ Successfully created admin user: ${email}`);
        console.log(`   UID: ${user.uid}`);
      } else {
        throw error;
      }
    }
    
    // Set custom admin claims
    await auth.setCustomUserClaims(user.uid, { admin: true });
    console.log(`✅ Admin privileges granted to ${email}`);
    
    // Verify the claims were set
    const updatedUser = await auth.getUser(user.uid);
    console.log('   Custom claims:', updatedUser.customClaims);
    
    console.log('\n🎉 Admin account is ready!');
    console.log('   Email:', email);
    console.log('   Password:', password);
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error.message);
    process.exit(1);
  }
  
  process.exit(0);
}

// Run the script
createAdminUser();
