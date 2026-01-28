# GitHub PAT Setup for IArchitecture Webhook

## Step 1: Create Personal Access Token (PAT)

1. Go to GitHub: https://github.com/settings/tokens/new
2. Fill in the form:
   - **Note**: `VendorCodeArchive-IArchitecture-Webhook`
   - **Expiration**: 90 days (or custom)
   - **Scopes** (check these boxes):
     - `repo` (Full control of private repositories)
     - `workflow` (Update GitHub Action workflows)

3. Click "Generate token"
4. **IMPORTANT**: Copy the token immediately (starts with `ghp_`)
   - You won't be able to see it again
   - Keep it secure - don't commit to git

## Step 2: Add PAT to VendorCodeArchive Secrets

1. Go to VendorCodeArchive repository: https://github.com/theIArchitecture/VendorCodeArchive
2. Click Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Configure:
   - **Name**: `IARCHITECTURE_PAT`
   - **Secret**: Paste the PAT from Step 1
5. Click "Add secret"

## Step 3: Verify Workflow File

The workflow file has been created at:
```
.github/workflows/trigger-iarchitecture.yml
```

This file will be pushed to GitHub in the next step.

## Step 4: Push to GitHub

After completing Steps 1-2, run:
```bash
cd "E:\Protected\VendorCodeArchive"
git push origin master
```

## Step 5: Test the Webhook

### Test PR Validation
1. Create a test branch:
   ```bash
   git checkout -b test-validation
   ```

2. Add a file with an architectural violation (example: use MD5):
   ```bash
   cd VendorCodeArchive/React
   cat > test-violation.cs << 'EOF'
   using System.Security.Cryptography;

   public class TestViolation
   {
       public void BadCrypto()
       {
           var md5 = new MD5CryptoServiceProvider(); // VIOLATION: FIPS non-compliant
       }
   }
   EOF
   git add test-violation.cs
   git commit -m "test: Add file with architectural violation"
   git push origin test-validation
   ```

3. Create PR on GitHub:
   - Go to: https://github.com/theIArchitecture/VendorCodeArchive
   - Click "Compare & pull request" for `test-validation` branch
   - Create the PR

4. Check workflow execution:
   - VendorCodeArchive Actions tab: Should see "Trigger IArchitecture Workflows" running
   - DemoRepo Actions tab: Should see "IArchitecture PR Validation" triggered
   - PR should get a comment with validation results

### Test Full Scan
1. Merge a PR to master branch
2. Check DemoRepo Actions: "IArchitecture Full Codebase Scan" should trigger
3. Verify it runs on self-hosted Windows runner

## Troubleshooting

### Workflow not triggering
- Check PAT hasn't expired: https://github.com/settings/tokens
- Verify PAT has correct scopes (repo, workflow)
- Check workflow run logs in VendorCodeArchive Actions tab

### "Resource not accessible by integration" error
- PAT is missing or has wrong scopes
- Recreate PAT with repo + workflow scopes

### DemoRepo workflow not triggering
- Check VendorCodeArchive workflow completed successfully
- Verify event_type matches: pr-validation or code-push
- Check DemoRepo Actions tab for triggered runs

## Security Notes

1. **Never commit the PAT** to the repository
2. **Rotate the PAT** every 90 days or when compromised
3. **Use minimal scopes** - only repo and workflow needed
4. **Store securely** - Use GitHub Secrets, never in code

## Next Steps After Setup

Once the webhook is configured and working:
1. Test PR validation with real violations
2. Test PR healing workflow (manual trigger)
3. Test full scan on main branch push
4. Verify dashboard updates automatically
5. Create test plan for systematic testing
