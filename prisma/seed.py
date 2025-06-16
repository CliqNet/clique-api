#!/usr/bin/env python3
"""
Seed script for populating the database with initial data
"""

import asyncio
import bcrypt
from datetime import datetime, timezone
from prisma import Prisma
from prisma.enums import UserType, AdminRole, AccountStatus

# Initialize Prisma client
prisma = Prisma()

async def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

async def create_permissions():
    """Create basic permissions"""
    permissions_data = [
        # Campaign permissions
        {"name": "create_campaign", "resource": "campaign", "action": "create"},
        {"name": "read_campaign", "resource": "campaign", "action": "read"},
        {"name": "update_campaign", "resource": "campaign", "action": "update"},
        {"name": "delete_campaign", "resource": "campaign", "action": "delete"},
        
        # Creator permissions
        {"name": "read_creator", "resource": "creator", "action": "read"},
        {"name": "update_creator", "resource": "creator", "action": "update"},
        {"name": "verify_creator", "resource": "creator", "action": "verify"},
        
        # Company permissions
        {"name": "read_company", "resource": "company", "action": "read"},
        {"name": "update_company", "resource": "company", "action": "update"},
        {"name": "verify_company", "resource": "company", "action": "verify"},
        
        # Analytics permissions
        {"name": "view_analytics", "resource": "analytics", "action": "read"},
        {"name": "view_all_analytics", "resource": "analytics", "action": "read_all"},
        
        # User management permissions
        {"name": "create_user", "resource": "user", "action": "create"},
        {"name": "read_user", "resource": "user", "action": "read"},
        {"name": "update_user", "resource": "user", "action": "update"},
        {"name": "delete_user", "resource": "user", "action": "delete"},
        {"name": "suspend_user", "resource": "user", "action": "suspend"},
        
        # Content permissions
        {"name": "create_content", "resource": "content", "action": "create"},
        {"name": "read_content", "resource": "content", "action": "read"},
        {"name": "update_content", "resource": "content", "action": "update"},
        {"name": "delete_content", "resource": "content", "action": "delete"},
        {"name": "publish_content", "resource": "content", "action": "publish"},
        
        # Social media permissions
        {"name": "connect_social", "resource": "social", "action": "connect"},
        {"name": "post_social", "resource": "social", "action": "post"},
        {"name": "read_social_stats", "resource": "social", "action": "read_stats"},
    ]
    
    print("Creating permissions...")
    created_permissions = []
    for perm_data in permissions_data:
        permission = await prisma.permission.upsert(
            where={"name": perm_data["name"]},
            data={
                "create": perm_data,
                "update": perm_data
            }
        )
        created_permissions.append(permission)
    
    print(f"Created {len(created_permissions)} permissions")
    return created_permissions

async def create_roles():
    """Create basic roles with permissions"""
    # Get all permissions
    all_permissions = await prisma.permission.find_many()
    perm_dict = {p.name: p.id for p in all_permissions}
    
    roles_data = [
        {
            "name": "creator_basic",
            "description": "Basic creator permissions - manage own profile and content",
            "permissions": [
                "read_creator", "update_creator", "create_content", "read_content", 
                "update_content", "delete_content", "publish_content", "connect_social", 
                "post_social", "read_social_stats", "view_analytics"
            ]
        },
        {
            "name": "creator_premium",
            "description": "Premium creator with advanced analytics",
            "permissions": [
                "read_creator", "update_creator", "create_content", "read_content", 
                "update_content", "delete_content", "publish_content", "connect_social", 
                "post_social", "read_social_stats", "view_analytics", "view_all_analytics"
            ]
        },
        {
            "name": "company_basic",
            "description": "Basic company permissions - create campaigns and view creators",
            "permissions": [
                "read_company", "update_company", "create_campaign", "read_campaign", 
                "update_campaign", "delete_campaign", "read_creator", "view_analytics"
            ]
        },
        {
            "name": "company_premium",
            "description": "Premium company with advanced features",
            "permissions": [
                "read_company", "update_company", "create_campaign", "read_campaign", 
                "update_campaign", "delete_campaign", "read_creator", "view_analytics",
                "view_all_analytics", "verify_creator"
            ]
        },
        {
            "name": "moderator",
            "description": "Moderator role - can verify users and moderate content",
            "permissions": [
                "read_user", "update_user", "suspend_user", "verify_creator", 
                "verify_company", "read_content", "update_content", "delete_content",
                "read_campaign", "update_campaign", "view_all_analytics"
            ]
        },
        {
            "name": "admin",
            "description": "Admin role - full access except user creation/deletion",
            "permissions": [
                p.name for p in all_permissions if p.name not in ["create_user", "delete_user"]
            ]
        },
        {
            "name": "super_admin",
            "description": "Super admin role - full system access",
            "permissions": [p.name for p in all_permissions]
        }
    ]
    
    print("Creating roles...")
    created_roles = []
    for role_data in roles_data:
        # Create role
        role = await prisma.role.upsert(
            where={"name": role_data["name"]},
            data={
                "create": {
                    "name": role_data["name"],
                    "description": role_data["description"]
                },
                "update": {
                    "description": role_data["description"]
                }
            }
        )
        
        # Clear existing permissions for this role
        await prisma.rolepermission.delete_many(
            where={"roleId": role.id}
        )
        
        # Add permissions to role
        for perm_name in role_data["permissions"]:
            if perm_name in perm_dict:
                await prisma.rolepermission.create(
                    data={
                        "roleId": role.id,
                        "permissionId": perm_dict[perm_name]
                    }
                )
        
        created_roles.append(role)
    
    print(f"Created {len(created_roles)} roles")
    return created_roles

async def create_admin_users():
    """Create initial admin users"""
    admin_users = [
        {
            "email": "superadmin@clique.com",
            "username": "superadmin",
            "password": "SuperAdmin123!",
            "firstName": "Super",
            "lastName": "Admin",
            "userType": UserType.ADMIN,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "admin_role": AdminRole.SUPER_ADMIN
        },
        {
            "email": "admin@clique.com",
            "username": "admin",
            "password": "Admin123!",
            "firstName": "System",
            "lastName": "Admin",
            "userType": UserType.ADMIN,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "admin_role": AdminRole.ADMIN
        },
        {
            "email": "moderator@clique.com",
            "username": "moderator",
            "password": "Moderator123!",
            "firstName": "Content",
            "lastName": "Moderator",
            "userType": UserType.ADMIN,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "admin_role": AdminRole.MODERATOR
        }
    ]
    
    print("Creating admin users...")
    created_admins = []
    
    # Get roles
    super_admin_role = await prisma.role.find_first(where={"name": "super_admin"})
    admin_role = await prisma.role.find_first(where={"name": "admin"})
    moderator_role = await prisma.role.find_first(where={"name": "moderator"})
    
    role_mapping = {
        AdminRole.SUPER_ADMIN: super_admin_role.id,
        AdminRole.ADMIN: admin_role.id,
        AdminRole.MODERATOR: moderator_role.id
    }
    
    for admin_data in admin_users:
        # Hash password
        hashed_password = await hash_password(admin_data["password"])
        
        # Create user
        user = await prisma.user.upsert(
            where={"email": admin_data["email"]},
            data={
                "create": {
                    **{k: v for k, v in admin_data.items() if k not in ["password", "admin_role"]},
                    "password": hashed_password
                },
                "update": {
                    **{k: v for k, v in admin_data.items() if k not in ["password", "admin_role"]},
                    "password": hashed_password
                }
            }
        )
        
        # Create admin profile
        await prisma.adminprofile.upsert(
            where={"userId": user.id},
            data={
                "create": {
                    "userId": user.id,
                    "role": admin_data["admin_role"]
                },
                "update": {
                    "role": admin_data["admin_role"]
                }
            }
        )
        
        # Assign role
        role_id = role_mapping.get(admin_data["admin_role"])
        if role_id:
            await prisma.userrole.upsert(
                where={"userId_roleId": {"userId": user.id, "roleId": role_id}},
                data={
                    "create": {"userId": user.id, "roleId": role_id},
                    "update": {}
                }
            )
        
        created_admins.append(user)
    
    print(f"Created {len(created_admins)} admin users")
    return created_admins

async def create_sample_creators():
    """Create sample creator users"""
    creators = [
        {
            "email": "john.creator@example.com",
            "username": "johncreator",
            "password": "Creator123!",
            "firstName": "John",
            "lastName": "Creator",
            "userType": UserType.CREATOR,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "profile": {
                "bio": "Tech content creator focusing on web development and AI",
                "niche": ["technology", "programming", "artificial-intelligence"],
                "totalFollowers": 15000,
                "avgEngagement": 4.2,
                "isVerified": True
            }
        },
        {
            "email": "sarah.lifestyle@example.com",
            "username": "sarahlifestyle",
            "password": "Creator123!",
            "firstName": "Sarah",
            "lastName": "Johnson",
            "userType": UserType.CREATOR,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "profile": {
                "bio": "Lifestyle and wellness content creator",
                "niche": ["lifestyle", "wellness", "fitness"],
                "totalFollowers": 8500,
                "avgEngagement": 5.1,
                "isVerified": False
            }
        }
    ]
    
    print("Creating sample creators...")
    created_creators = []
    
    # Get creator role
    creator_role = await prisma.role.find_first(where={"name": "creator_basic"})
    
    for creator_data in creators:
        # Hash password
        hashed_password = await hash_password(creator_data["password"])
        
        # Create user
        user = await prisma.user.upsert(
            where={"email": creator_data["email"]},
            data={
                "create": {
                    **{k: v for k, v in creator_data.items() if k not in ["password", "profile"]},
                    "password": hashed_password
                },
                "update": {
                    **{k: v for k, v in creator_data.items() if k not in ["password", "profile"]},
                    "password": hashed_password
                }
            }
        )
        
        # Create creator profile
        await prisma.creatorprofile.upsert(
            where={"userId": user.id},
            data={
                "create": {
                    "userId": user.id,
                    **creator_data["profile"]
                },
                "update": creator_data["profile"]
            }
        )
        
        # Assign role
        if creator_role:
            await prisma.userrole.upsert(
                where={"userId_roleId": {"userId": user.id, "roleId": creator_role.id}},
                data={
                    "create": {"userId": user.id, "roleId": creator_role.id},
                    "update": {}
                }
            )
        
        created_creators.append(user)
    
    print(f"Created {len(created_creators)} sample creators")
    return created_creators

async def create_sample_companies():
    """Create sample company users"""
    companies = [
        {
            "email": "marketing@techstartup.com",
            "username": "techstartup",
            "password": "Company123!",
            "firstName": "Tech",
            "lastName": "Startup",
            "userType": UserType.COMPANY,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "profile": {
                "companyName": "TechStartup Inc",
                "industry": "Technology",
                "website": "https://techstartup.com",
                "description": "Innovative SaaS solutions for modern businesses"
            }
        },
        {
            "email": "brand@fashionco.com",
            "username": "fashionco",
            "password": "Company123!",
            "firstName": "Fashion",
            "lastName": "Company",
            "userType": UserType.COMPANY,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.now(timezone.utc),
            "profile": {
                "companyName": "Fashion Co",
                "industry": "Fashion & Retail",
                "website": "https://fashionco.com",
                "description": "Sustainable fashion brand for the modern consumer"
            }
        }
    ]
    
    print("Creating sample companies...")
    created_companies = []
    
    # Get company role
    company_role = await prisma.role.find_first(where={"name": "company_basic"})
    
    for company_data in companies:
        # Hash password
        hashed_password = await hash_password(company_data["password"])
        
        # Create user
        user = await prisma.user.upsert(
            where={"email": company_data["email"]},
            data={
                "create": {
                    **{k: v for k, v in company_data.items() if k not in ["password", "profile"]},
                    "password": hashed_password
                },
                "update": {
                    **{k: v for k, v in company_data.items() if k not in ["password", "profile"]},
                    "password": hashed_password
                }
            }
        )
        
        # Create company profile
        await prisma.companyprofile.upsert(
            where={"userId": user.id},
            data={
                "create": {
                    "userId": user.id,
                    **company_data["profile"]
                },
                "update": company_data["profile"]
            }
        )
        
        # Assign role
        if company_role:
            await prisma.userrole.upsert(
                where={"userId_roleId": {"userId": user.id, "roleId": company_role.id}},
                data={
                    "create": {"userId": user.id, "roleId": company_role.id},
                    "update": {}
                }
            )
        
        created_companies.append(user)
    
    print(f"Created {len(created_companies)} sample companies")
    return created_companies

async def main():
    """Main seed function"""
    try:
        await prisma.connect()
        print("Connected to database")
        
        # Create permissions first
        await create_permissions()
        
        # Create roles (depends on permissions)
        await create_roles()
        
        # Create users (depends on roles)
        await create_admin_users()
        await create_sample_creators()
        await create_sample_companies()
        
        print("\n✅ Database seeded successfully!")
        print("\nDefault admin credentials:")
        print("Super Admin: superadmin@yourapp.com / SuperAdmin123!")
        print("Admin: admin@yourapp.com / Admin123!")
        print("Moderator: moderator@yourapp.com / Moderator123!")
        print("\nSample Creator: john.creator@example.com / Creator123!")
        print("Sample Company: marketing@techstartup.com / Company123!")
        
    except Exception as e:
        print(f"❌ Error seeding database: {e}")
        raise
    finally:
        await prisma.disconnect()
        print("Disconnected from database")

if __name__ == "__main__":
    asyncio.run(main())