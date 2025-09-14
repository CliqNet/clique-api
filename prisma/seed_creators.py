#!/usr/bin/env python3
"""
Seed script to create 5 South African creators for the network screen
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
import hashlib
import uuid

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.lib.prisma import prisma
from app.utils.auth_utils import hash_password
from prisma.enums import UserType, AccountStatus, PlanType


SOUTH_AFRICAN_CREATORS = [
    {
        "email": "nomsa.mokwena@gmail.com",
        "username": "nomsa_style",
        "displayName": "Nomsa Mokwena",
        "bio": "Fashion influencer from Cape Town 🇿🇦 | Sustainable fashion advocate | Style tips for the modern African woman",
        "location": "Cape Town, South Africa",
        "website": "https://nomsa-style.co.za",
        "avatar": "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=400&h=400&fit=crop&crop=face",
        "categories": ["FASHION", "LIFESTYLE"],
        "followers": 45000,
        "engagement": 8.5,
        "verified": True,
        "social_accounts": [
            {
                "platform": "INSTAGRAM",
                "username": "nomsa_style",
                "followers": 35000,
                "engagement": 9.2
            },
            {
                "platform": "TIKTOK",
                "username": "nomsa_style",
                "followers": 10000,
                "engagement": 7.8
            }
        ]
    },
    {
        "email": "thabo.fitness@gmail.com",
        "username": "thabo_transforms",
        "displayName": "Thabo Mthembu",
        "bio": "Fitness coach & transformation specialist from Joburg 💪 | Helping South Africans get fit | Certified personal trainer",
        "location": "Johannesburg, South Africa",
        "website": "https://thabo-fitness.co.za",
        "avatar": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&crop=face",
        "categories": ["FITNESS", "HEALTH"],
        "followers": 28000,
        "engagement": 12.3,
        "verified": True,
        "social_accounts": [
            {
                "platform": "INSTAGRAM",
                "username": "thabo_transforms",
                "followers": 18000,
                "engagement": 13.1
            },
            {
                "platform": "YOUTUBE",
                "username": "Thabo Transforms",
                "followers": 10000,
                "engagement": 11.5
            }
        ]
    },
    {
        "email": "zandi.eats@gmail.com",
        "username": "zandi_eats",
        "displayName": "Zandi Nkosi",
        "bio": "Food blogger celebrating South African cuisine 🍴 | Traditional recipes with a modern twist | Durban foodie",
        "location": "Durban, South Africa",
        "website": "https://zandi-eats.co.za",
        "avatar": "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=400&h=400&fit=crop&crop=face",
        "categories": ["FOOD", "LIFESTYLE"],
        "followers": 52000,
        "engagement": 7.8,
        "verified": True,
        "social_accounts": [
            {
                "platform": "INSTAGRAM",
                "username": "zandi_eats",
                "followers": 32000,
                "engagement": 8.4
            },
            {
                "platform": "TIKTOK",
                "username": "zandi_eats",
                "followers": 20000,
                "engagement": 7.2
            }
        ]
    },
    {
        "email": "sipho.tech@gmail.com",
        "username": "sipho_codes",
        "displayName": "Sipho Radebe",
        "bio": "Tech entrepreneur & content creator 👨‍💻 | Building the future of African tech | Python & AI enthusiast",
        "location": "Cape Town, South Africa",
        "website": "https://sipho-codes.dev",
        "avatar": "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=400&h=400&fit=crop&crop=face",
        "categories": ["TECH", "BUSINESS"],
        "followers": 38000,
        "engagement": 11.2,
        "verified": False,
        "social_accounts": [
            {
                "platform": "YOUTUBE",
                "username": "Sipho Codes",
                "followers": 25000,
                "engagement": 12.8
            },
            {
                "platform": "TWITTER",
                "username": "sipho_codes",
                "followers": 13000,
                "engagement": 9.6
            }
        ]
    },
    {
        "email": "lerato.beauty@gmail.com",
        "username": "lerato_glam",
        "displayName": "Lerato Dlamini",
        "bio": "Beauty & wellness creator ✨ | Celebrating natural African beauty | Skincare tips for melanin-rich skin",
        "location": "Pretoria, South Africa",
        "website": "https://lerato-glam.co.za",
        "avatar": "https://images.unsplash.com/photo-1509967419530-da38b4704bc6?w=400&h=400&fit=crop&crop=face",
        "categories": ["BEAUTY", "WELLNESS"],
        "followers": 67000,
        "engagement": 9.7,
        "verified": True,
        "social_accounts": [
            {
                "platform": "INSTAGRAM",
                "username": "lerato_glam",
                "followers": 45000,
                "engagement": 10.5
            },
            {
                "platform": "TIKTOK",
                "username": "lerato_glam",
                "followers": 22000,
                "engagement": 8.9
            }
        ]
    }
]


async def create_creator_user(creator_data):
    """Create a creator user with profile and social accounts"""

    # Extract first and last name from display name
    name_parts = creator_data["displayName"].split()
    first_name = name_parts[0] if name_parts else "Creator"
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

    # Create user
    user = await prisma.user.create(
        data={
            "email": creator_data["email"],
            "username": creator_data["username"],
            "password": hash_password("TempPassword123!"),  # Default password
            "firstName": first_name,
            "lastName": last_name,
            "userType": UserType.CREATOR,
            "status": AccountStatus.ACTIVE,
            "isVerified": True,
            "emailVerifiedAt": datetime.utcnow()
        }
    )

    # Create creator profile
    creator_profile = await prisma.creatorprofile.create(
        data={
            "userId": user.id,
            "bio": creator_data["bio"],
            "niche": creator_data["categories"],
            "totalFollowers": creator_data["followers"],
            "avgEngagement": creator_data["engagement"],
            "isVerified": creator_data["verified"],
            "plan": PlanType.FREE
        }
    )

    # Create social accounts
    for social_account in creator_data["social_accounts"]:
        await prisma.socialaccount.create(
            data={
                "userId": user.id,
                "creatorId": creator_profile.id,
                "platform": social_account["platform"],
                "platformId": f"{social_account['platform'].lower()}_{creator_data['username']}",
                "username": social_account["username"],
                "accessToken": f"fake_token_{uuid.uuid4()}",  # Fake token for seeding
                "tokenType": "Bearer",
                "isActive": True
            }
        )

    return user, creator_profile


async def main():
    """Main seeding function"""
    try:
        await prisma.connect()
        print("🌱 Starting South African creators seeding...")

        created_count = 0

        for creator_data in SOUTH_AFRICAN_CREATORS:
            try:
                # Check if user already exists
                existing_user = await prisma.user.find_unique(
                    where={"email": creator_data["email"]}
                )

                if existing_user:
                    print(f"⚠️  Creator {creator_data['displayName']} already exists, skipping...")
                    continue

                user, creator_profile = await create_creator_user(creator_data)
                created_count += 1

                print(f"✅ Created creator: {creator_data['displayName']} (@{creator_data['username']})")
                print(f"   - Email: {creator_data['email']}")
                print(f"   - Location: {creator_data['location']}")
                print(f"   - Followers: {creator_data['followers']:,}")
                print(f"   - Categories: {', '.join(creator_data['categories'])}")
                print(f"   - Social accounts: {len(creator_data['social_accounts'])}")
                print()

            except Exception as e:
                print(f"❌ Failed to create creator {creator_data['displayName']}: {str(e)}")
                continue

        print(f"🎉 Seeding completed! Created {created_count} South African creators.")
        print()
        print("📱 These creators will now appear in your network screen!")
        print("🔑 Default password for all seeded creators: TempPassword123!")

    except Exception as e:
        print(f"💥 Seeding failed: {str(e)}")
        sys.exit(1)
    finally:
        await prisma.disconnect()


if __name__ == "__main__":
    asyncio.run(main())