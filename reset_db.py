from app import db, app

with app.app_context():
    db.create_all()
    print("✅ Base de données recréée avec succès !")
