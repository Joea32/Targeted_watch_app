from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1ec56cb0af11'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=200),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.alter_column('profile_pic',
               existing_type=sa.VARCHAR(length=200),
               type_=sa.String(length=255),
               existing_nullable=True)
        batch_op.alter_column('proof_file',
               existing_type=sa.VARCHAR(length=200),
               type_=sa.String(length=255),
               existing_nullable=True)
        batch_op.drop_column('media_filename')
        batch_op.add_column(sa.Column('email', sa.String(length=150), nullable=True))

        # Create the unique constraint with a name INSIDE batch_op to avoid the Alembic error
        batch_op.create_unique_constraint('uq_users_email', ['email'])

    # Remove separate op.execute for index creation since the constraint covers uniqueness

def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        # Drop the unique constraint by name
        batch_op.drop_constraint('uq_users_email', type_='unique')
        batch_op.drop_column('email')

        batch_op.add_column(sa.Column('media_filename', sa.String(length=255), nullable=True))
        batch_op.alter_column('proof_file',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=200),
               existing_nullable=True)
        batch_op.alter_column('profile_pic',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=200),
               existing_nullable=True)
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=200),
               existing_nullable=False)