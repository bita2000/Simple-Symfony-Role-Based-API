<?php
namespace App\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use App\Entity\User;
use App\Entity\Company;
use Symfony\Component\HttpFoundation\Response;

class ApiTest extends WebTestCase
{
    private $client;
    private $entityManager;

    protected function setUp(): void
    {
        parent::setUp();
        self::ensureKernelShutdown();
        $this->client = static::createClient();

        $this->entityManager = self::getContainer()->get('doctrine')->getManager();

        $this->resetDatabase();
    }

    public function testGetUsersAccessControl()
    {
        $company1 = $this->createCompany('Company One');
        $company2 = $this->createCompany('Company Two');

        $user1 = $this->createUser('user1@example.com', 'password', ['ROLE_USER'], $company1);
        $user2 = $this->createUser('user2@example.com', 'password', ['ROLE_USER'], $company2);
        $companyAdmin = $this->createUser('admin@example.com', 'password', ['ROLE_COMPANY_ADMIN'], $company1);
        $superAdmin = $this->createUser('superadmin@example.com', 'password', ['ROLE_SUPER_ADMIN'], null);

        // Authenticate as USER (user1)
        $token = $this->authenticate('user1@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('GET', '/api/users');
        $this->assertResponseIsSuccessful();

        $responseData = json_decode($this->client->getResponse()->getContent(), true);
        $this->assertCount(1, $responseData);
        $this->assertEquals('user1@example.com', $responseData[0]['email']);

        // Authenticate as COMPANY_ADMIN (admin)
        $token = $this->authenticate('admin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('GET', '/api/users');
        $this->assertResponseIsSuccessful();

        $responseData = json_decode($this->client->getResponse()->getContent(), true);
        $this->assertCount(2, $responseData);
        $emails = array_column($responseData, 'email');
        $this->assertContains('user1@example.com', $emails);
        $this->assertContains('admin@example.com', $emails);

        // Authenticate as SUPER_ADMIN
        $token = $this->authenticate('superadmin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('GET', '/api/users');
        $this->assertResponseIsSuccessful();

        $responseData = json_decode($this->client->getResponse()->getContent(), true);
        $this->assertCount(4, $responseData);
    }

    public function testPostUsersAccessControl()
    {
        $company = $this->createCompany('Test Company');

        $token = $this->authenticate('user@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('POST', '/api/users', [], [], [], json_encode([
            'email' => 'newuser@example.com',
            'password' => 'password',
            'name' => 'New User',
            'roles' => ['ROLE_USER']
        ]));

        $this->assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Authenticate as COMPANY_ADMIN
        $token = $this->authenticate('admin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('POST', '/api/users', [], [], [], json_encode([
            'email' => 'newuser@example.com',
            'password' => 'password',
            'name' => 'New User',
            'roles' => ['ROLE_USER']
        ]));

        $this->assertResponseStatusCodeSame(Response::HTTP_CREATED);

        // Authenticate as SUPER_ADMIN
        $token = $this->authenticate('superadmin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('POST', '/api/users', [], [], [], json_encode([
            'email' => 'anotheruser@example.com',
            'password' => 'password',
            'name' => 'Another User',
            'roles' => ['ROLE_USER'],
            'company_id' => $company->getId()
        ]));

        $this->assertResponseStatusCodeSame(Response::HTTP_CREATED);
    }

    public function testDeleteUserAccessControl()
    {
        $company = $this->createCompany('Test Company');
        $user = $this->createUser('user@example.com', 'password', ['ROLE_USER'], $company);

        $token = $this->authenticate('user@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('DELETE', '/api/users/' . $user->getId());
        $this->assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Authenticate as COMPANY_ADMIN
        $token = $this->authenticate('admin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('DELETE', '/api/users/' . $user->getId());
        $this->assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Authenticate as SUPER_ADMIN
        $token = $this->authenticate('superadmin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        $this->client->request('DELETE', '/api/users/' . $user->getId());
        $this->assertResponseStatusCodeSame(Response::HTTP_NO_CONTENT);
    }

    public function testCompanyEndpointsAccessControl()
    {
        $company = $this->createCompany('Company One');

        $token = $this->authenticate('user@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        // Test GET /companies
        $this->client->request('GET', '/api/companies');
        $this->assertResponseIsSuccessful();

        // Test GET /companies/{id}
        $this->client->request('GET', '/api/companies/' . $company->getId());
        $this->assertResponseIsSuccessful();

        // Test POST /companies
        $this->client->request('POST', '/api/companies', [], [], [], json_encode([
            'name' => 'New Company'
        ]));
        $this->assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Authenticate as SUPER_ADMIN
        $token = $this->authenticate('superadmin@example.com', 'password');
        $this->client->setServerParameter('HTTP_Authorization', sprintf('Bearer %s', $token));

        // Test POST /companies
        $this->client->request('POST', '/api/companies', [], [], [], json_encode([
            'name' => 'New Company'
        ]));
        $this->assertResponseStatusCodeSame(Response::HTTP_CREATED);
    }

    private function createCompany(string $name): Company
    {
        $company = new Company();
        $company->setName($name);

        $this->entityManager->persist($company);
        $this->entityManager->flush();

        return $company;
    }

    private function createUser(string $email, string $password, array $roles, ?Company $company): User
    {
        $user = new User();
        $user->setEmail($email);
        $user->setName('Test User');
        $user->setRoles($roles);
        $user->setCompany($company);

        // Hash the password
        $passwordHasher = self::getContainer()->get('security.password_hasher');
        $hashedPassword = $passwordHasher->hashPassword($user, $password);
        $user->setPassword($hashedPassword);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    private function authenticate(string $email, string $password): string
    {
        $this->client->request('POST', '/login', [], [], ['CONTENT_TYPE' => 'application/json'], json_encode([
            'email' => $email,
            'password' => $password
        ]));

        $response = $this->client->getResponse();

         $this->assertTrue($response->isSuccessful(), "Authentication failed for user: $email");

        $responseData = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('token', $responseData, "Token not found in the response for user: $email");

        return $responseData['token'];
    }

    private function authenticateAsSuperAdmin(): string
    {
        $superAdmin = $this->createUser('superadmin@example.com', 'password', ['ROLE_SUPER_ADMIN'], null);
        return $this->authenticate('superadmin@example.com', 'password');
    }

    private function resetDatabase(): void
    {
        $schemaTool = new \Doctrine\ORM\Tools\SchemaTool($this->entityManager);
        $metadata = $this->entityManager->getMetadataFactory()->getAllMetadata();

        if (!empty($metadata)) {
            $schemaTool->dropSchema($metadata);
            $schemaTool->createSchema($metadata);
        }
    }

    public function tearDown(): void
    {
        parent::tearDown();
        $this->entityManager->close();
    }
}
