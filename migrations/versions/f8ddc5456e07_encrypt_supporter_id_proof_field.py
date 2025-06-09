"""Encrypt supporter_id_proof field

Revision ID: f8ddc5456e07
Revises: f3f2c24073d8
Create Date: 2025-06-08 19:45:37.629991

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f8ddc5456e07'
down_revision = 'f3f2c24073d8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('message', sa.LargeBinary(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('read', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('supporter_id_proof')  # drop old column
        batch_op.drop_column('bio')                  # drop old column
        
        # add new encrypted columns
        batch_op.add_column(sa.Column('_supporter_id_proof', sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column('_bio', sa.LargeBinary(), nullable=True))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('_supporter_id_proof')
        batch_op.drop_column('_bio')
        batch_op.add_column(sa.Column('bio', sa.TEXT(), nullable=True))
        batch_op.add_column(sa.Column('supporter_id_proof', sa.VARCHAR(length=255), nullable=True))

    op.drop_table('alerts')
